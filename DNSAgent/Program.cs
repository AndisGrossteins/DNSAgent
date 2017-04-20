using System;
using System.Collections.Generic;
using System.Configuration.Install;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

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

        private const string OptionsFileName = "options.cfg";
        private const string RulesFileName = "rules.cfg";
        private static readonly List<DnsAgent> DnsAgents = new List<DnsAgent>();
        private static NotifyIcon _notifyIcon;
        private static ContextMenu _contextMenu;
        private static readonly DnsMessageCache AgentCommonCache = new DnsMessageCache();

        private static void Main(string[] args)
        {

            Directory.SetCurrentDirectory(AppDomain.CurrentDomain.BaseDirectory);

            if (!Environment.UserInteractive) // Running as service
            {
                using (var service = new Service())
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
                        Start(args);
                        break;
                }
            }
        }

        private static void Start(string[] args)
        {

            var version = Assembly.GetExecutingAssembly().GetName().Version;
            var buildTime = Utils.RetrieveLinkerTimestamp(Assembly.GetExecutingAssembly().Location);
            var programName = $"DNSAgent {version.Major}.{version.Minor}.{version.Build}";
            logger.Info($"{programName} (built on {buildTime.ToString(CultureInfo.CurrentCulture)})");
            logger.Info("Starting DNSAgent...");

            var options = ReadOptions();
            var rules = ReadRules();
            var listenEndpoints = options.ListenOn.Split(',');
            var startedEvent = new CountdownEvent(listenEndpoints.Length);
            lock (DnsAgents)
            {
                foreach (var listenOn in listenEndpoints)
                {
                    var agent = new DnsAgent(options, rules, listenOn.Trim(), AgentCommonCache);
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
                Console.WriteLine("Press Ctrl-R to reload configurations, Ctrl-Q to stop and quit.");

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

                var hideMenuItem = new MenuItem(options.HideOnStart ? "Show" : "Hide");
                if (options.HideOnStart)
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

        private static void Stop(bool pressAnyKeyToContinue = true)
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
                _notifyIcon.Dispose();
                _contextMenu.Dispose();
                if (pressAnyKeyToContinue)
                    PressAnyKeyToContinue();
                Application.Exit();
            }
        }

        private static void Reload()
        {
            var options = ReadOptions();
            var rules = ReadRules();
            lock (DnsAgents)
            {
                foreach (var agent in DnsAgents)
                {
                    agent.Options = options;
                    agent.Rules = rules;
                }
            }
            AgentCommonCache.Clear();
            logger.Info("Options and rules reloaded. Cache cleared.");
        }

        private static void PressAnyKeyToContinue()
        {
            logger.Info("Press any key to continue . . . ");
            Console.ReadKey(true);
        }

        #region Nested class to support running as service

        private class Service : ServiceBase
        {
            public Service()
            {
                ServiceName = "DNSAgent";
            }

            protected override void OnStart(string[] args)
            {
                Start(args);
                base.OnStart(args);
            }

            protected override void OnStop()
            {
                Program.Stop();
                base.OnStop();
            }
        }

        #endregion

        #region Win32 API Import

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetConsoleWindow();

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        private const int SwHide = 0;
        private const int SwShow = 5;

        #endregion

        #region Util functions to read rules

        private static Options ReadOptions()
        {
            Options options;
            if (File.Exists(Path.Combine(Environment.CurrentDirectory, OptionsFileName)))
            {
                options = JsonConvert.DeserializeObject<Options>(
                    File.ReadAllText(Path.Combine(Environment.CurrentDirectory, OptionsFileName)));
            }
            else
            {
                options = new Options();
                File.WriteAllText(Path.Combine(Environment.CurrentDirectory, OptionsFileName),
                    JsonConvert.SerializeObject(options, Formatting.Indented));
            }
            return options;
        }

        private static Rules ReadRules()
        {
            Rules rules;
            using (
                var file = File.Open(Path.Combine(Environment.CurrentDirectory, RulesFileName), FileMode.OpenOrCreate))
            using (var reader = new StreamReader(file))
            using (var jsonTextReader = new JsonTextReader(reader))
            {
                var serializer = JsonSerializer.CreateDefault();
                rules = serializer.Deserialize<Rules>(jsonTextReader) ?? new Rules();
            }
            return rules;
        }

        #endregion
    }
}