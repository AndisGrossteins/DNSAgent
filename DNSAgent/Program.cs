using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

using Microsoft.Extensions.Configuration;


using log4net;
using log4net.Config;
using Newtonsoft.Json;

using DNSAgent;

namespace DnsAgent
{
    internal class Program
    {
        private static readonly ILog logger =
                LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        private const string OptionsFileName = "options.json";
        private const string RulesFileName = "rules.json";

        private static void Main(string[] args)
        {

            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            var program = new Program();

            if (!Environment.UserInteractive) // Running as service
            {
                using (var service = new Service(program))
                    ServiceBase.Run(service);
            }
            else // Running as console app
            {
                var parameter = string.Concat(args);
                switch (parameter)
                {
                    case "--install":
                        ManagedInstallerClass.InstallHelper(new[]
                        {"/LogFile=", Assembly.GetExecutingAssembly().Location});
                        break;

                    case "--uninstall":
                        ManagedInstallerClass.InstallHelper(new[]
                        {"/LogFile=", "/u", Assembly.GetExecutingAssembly().Location});
                        break;

                    default:
                        program.Start(args);
                        break;
                }
            }
        }

        private NotifyIcon _notifyIcon;
        private ContextMenu _contextMenu;

        private IConfiguration Configuration { get; set; }
        private readonly List<DnsAgent> DnsAgents = new List<DnsAgent>();
        private readonly DnsMessageCache AgentCommonCache = new DnsMessageCache();

        public AppConf AppConf
        {
            get; set;
        } = new AppConf();
        public List<IPNetwork> AllowedClientIPs { get; set; } = new List<IPNetwork>();

        public Program()
        {
			try
			{
				var builder = new ConfigurationBuilder()
					.SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
					.AddJsonFile(OptionsFileName, optional: true, reloadOnChange: true);
				Configuration = builder.Build();
				Configuration.GetSection("AppConfiguration").Bind(AppConf);
				logger.Debug("Options Loaded");
			}
			catch (Exception ex)
			{
				logger.Error("Error loading configuration", ex);
			}
        }

        private void Start(string[] args)
        {
            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var buildTime = Utils.RetrieveLinkerTimestamp(Assembly.GetExecutingAssembly().Location);
            var programName = $"DNSAgent {version.Major}.{version.Minor}.{version.Build}";
            logger.Info($"{programName} (built on {buildTime.ToString(CultureInfo.CurrentCulture)})");
            logger.Info("Starting DNSAgent...");

            var rules = LoadRules();
            var listenEndpoints = AppConf.ListenOn.Split(',');
            var startedEvent = new CountdownEvent(listenEndpoints.Length);
            lock (DnsAgents)
            {
                foreach (var listenOn in listenEndpoints)
                {
                    var agent = new DnsAgent(AppConf, rules, listenOn.Trim(), AgentCommonCache);
                    agent.Started += () => startedEvent.Signal();
                    DnsAgents.Add(agent);
                }
            }
            if (Environment.UserInteractive)
            {
                lock (DnsAgents)
                {
                    if (DnsAgents.Any(agent => !agent.Start()))
                    {
                        PressAnyKeyToContinue();
                        return;
                    }
                }
                startedEvent.Wait();
                logger.Info("DNSAgent has been started.");
                Console.WriteLine("Press Ctrl-R to reload rules and clear global cache, Ctrl-Q to stop and quit.");

                Task.Run(() =>
                {
                    var exit = false;
                    while (!exit)
                    {
                        var keyInfo = Console.ReadKey(true);
                        if (keyInfo.Modifiers != ConsoleModifiers.Control) continue;
                        switch (keyInfo.Key)
                        {
                            case ConsoleKey.R: // Reload options.cfg and rules.cfg
                                Reload();
                                break;

                            case ConsoleKey.Q:
                                exit = true;
                                Stop();
                                break;
                        }
                    }
                });

                var hideMenuItem = new MenuItem(AppConf.HideOnStart ? "Show" : "Hide");
                if (AppConf.HideOnStart)
                    ShowWindow(GetConsoleWindow(), SwHide);
                hideMenuItem.Click += (sender, eventArgs) =>
                {
                    if (hideMenuItem.Text == "Hide")
                    {
                        ShowWindow(GetConsoleWindow(), SwHide);
                        hideMenuItem.Text = "Show";
                    }
                    else
                    {
                        ShowWindow(GetConsoleWindow(), SwShow);
                        hideMenuItem.Text = "Hide";
                    }
                };
                _contextMenu = new ContextMenu(new[]
                {
                    hideMenuItem,
                    new MenuItem("Reload", (sender, eventArgs) => Reload()),
                    new MenuItem("Exit", (sender, eventArgs) => Stop(false))
                });
                _notifyIcon = new NotifyIcon
                {
                    Icon = Icon.ExtractAssociatedIcon(Assembly.GetExecutingAssembly().Location),
                    ContextMenu = _contextMenu,
                    Text = programName,
                    Visible = true
                };
                _notifyIcon.MouseClick += (sender, eventArgs) =>
                {
                    if (eventArgs.Button == MouseButtons.Left)
                        hideMenuItem.PerformClick();
                };

                Application.ApplicationExit += new EventHandler((sender, eventArgs) => CleanIcon());

                SetConsoleCtrlHandler(new ConsoleEventDelegate((eventType) =>
                {
                    if (eventType == CtrlTypes.CTRL_CLOSE_EVENT)
                    {
                        CleanIcon();
                    }
                    return false;
                }), true);

                Application.Run();
            }
            else
            {
                lock (DnsAgents)
                {
                    foreach (var agent in DnsAgents)
                    {
                        agent.Start();
                    }
                }
                logger.Info("DNSAgent has been started.");
            }
        }

        private void Stop(bool pressAnyKeyToContinue = true)
        {
            lock (DnsAgents)
            {
                DnsAgents.ForEach(agent =>
                {
                    agent.Stop();
                });
            }
            logger.Info("DNSAgent has been stopped.");

            if (Environment.UserInteractive)
            {

                if (pressAnyKeyToContinue)
                {
                    CleanIcon();
                    PressAnyKeyToContinue();
                }
                Application.Exit();
            }
        }

		private void CleanIcon()
		{
			if (_notifyIcon == null) { return; }
			_notifyIcon.Dispose();
			_notifyIcon = null;
			_contextMenu?.Dispose();
			_contextMenu = null;
		}


		private static void PressAnyKeyToContinue()
        {
			Console.WriteLine("Press any key to continue ...");
			Console.ReadKey(true);
        }



        #region Nested class to support running as service

        private class Service : ServiceBase
        {
            private Program _program;
            public Service(Program program)
            {
                ServiceName = "DNSAgent";
                _program = program;
            }

            protected override void OnStart(string[] args)
            {
                _program.Start(args);
                base.OnStart(args);
            }

            protected override void OnStop()
            {
                _program.Stop();
                base.OnStop();
            }
        }

        #endregion

        #region Win32 API Import

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        public enum CtrlTypes
        {
            CTRL_C_EVENT = 0,
            CTRL_BREAK_EVENT,
            CTRL_CLOSE_EVENT,
            CTRL_LOGOFF_EVENT = 5,
            CTRL_SHUTDOWN_EVENT
        }


        private delegate bool ConsoleEventDelegate(CtrlTypes eventType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleCtrlHandler(ConsoleEventDelegate callback, bool add);

        private const int SwHide = 0;
        private const int SwShow = 5;

        #endregion

        #region Util functions to read rules

        private Rules LoadRules()
        {
            Rules rules;
            using (
                var file = File.Open(Path.Combine(Environment.CurrentDirectory, RulesFileName), FileMode.OpenOrCreate))
            using (var reader = new StreamReader(file))
            using (var jsonTextReader = new JsonTextReader(reader))
            {
                var serializer = JsonSerializer.CreateDefault();
				try {
					rules = serializer.Deserialize<Rules>(jsonTextReader) ?? new Rules();
				} catch (Exception ex) {
					logger.Error("Failed loading rules", ex);
					rules = new Rules();
				}
            }
            return rules;
        }

        #endregion

        private void Reload()
        {
            var rules = LoadRules();
			if ( rules.Count > 0 )
			{
				lock (DnsAgents)
				{
					foreach (var agent in DnsAgents)
					{
						agent.Rules = rules;
					}
				}
				logger.Info("Rules reloaded.");
			} else {
				logger.WarnFormat("Rules not reloaded. Please check {0} file for errors", RulesFileName);
			}
			AgentCommonCache.Clear();
            logger.Info("Cache cleared.");
        }

    }
}