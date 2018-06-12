using System.Collections.Generic;

using System.Net;

namespace DNSAgent
{
    internal class AppConf
    {
        /// <summary>
        ///     Set to true to automatically hide the window on start.
        /// </summary>
        public bool HideOnStart { get; set; } = false;

        /// <summary>
        ///     IP and port that DNSAgent will listen on. 0.0.0.0:53 for all interfaces and 127.0.0.1:53 for localhost. Of course
        ///     you can use other ports.
        /// </summary>
        public string ListenOn { get; set; } = "127.0.0.1";

        /// <summary>
        ///     Querys that don't match any rules will be send to this server.
        /// </summary>
        public string LocalNameServer { get; set; } = "119.29.29.29";

        /// <summary>
        ///     Querys that don't match any rules will be send to this server.
        /// </summary>
        public string WorldNameServer { get; set; } = "8.8.8.8";

        /// <summary>
        ///     Whether to use DNSPod HttpDNS protocol to query the name server for A record.
        /// </summary>
        public bool UseHttpQuery { get; set; } = false;

        /// <summary>
        ///     Timeout for a query, in milliseconds. This may be overridden by rules.cfg for a specific domain name.
        /// </summary>
        public int QueryTimeout { get; set; } = 4000;

        /// <summary>
        ///     Whether to enable compression pointer mutation to query the default name servers. This may avoid MITM attack in
        ///     some network environments.
        /// </summary>
        public bool CompressionMutation { get; set; } = false;

        /// <summary>
        ///     Whether to enable caching of responses.
        /// </summary>
        public bool CacheResponse { get; set; } = true;

        /// <summary>
        ///     How long will the cached response live. If a DNS record's TTL is longer than this value, it will be used instead of
        ///     this. Set to 0 to use the original TTL.
        /// </summary>
        public int CacheAge { get; set; } = 0;

        /// <summary>
        ///     Source network whitelist. Only IPs from these network are accepted. Set to null to accept all IP (disable
        ///     whitelist), empty to deny all IP.
        /// </summary>
        public List<string> NetworkWhitelist {
            get { return _networkWhitelist; }
            set
            {
                _networkWhitelist = value;

                AllowedClientIPs = new List<IPNetwork>();
                if (value == null)
                    return;
                foreach (var ipaddr in value)
                {
                    var ipNetwork = IPNetwork.Parse(ipaddr);
                    if (ipNetwork != null)
                    {
                        AllowedClientIPs.Add(ipNetwork);
                    }
                }
            }
        }
        private List<string> _networkWhitelist = new List<string>();

        /// <summary>
        /// Derived properties    
        /// Source network whitelist. 
        /// </summary>
        public List<IPNetwork> AllowedClientIPs { get; set; } = new List<IPNetwork>();


    }
}