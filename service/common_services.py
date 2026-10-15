"""
TCPrax Curated Common-Service Dataset

An organized, version-controlled catalog of common TCP services with
their registered ports and a category.

Source and methodology (see also NOTICE and README):
    Port/service assignments follow IANA's Service Name and Transport
    Protocol Port Number Registry
    (https://www.iana.org/assignments/service-names-port-numbers/).
    IANA does NOT publish a "most common services" ranking, so this is a
    *curated* selection based on IANA registrations supplemented by
    public service-usage knowledge; it is described as such, not as an
    authoritative popularity list.

Each entry maps a human/registered service name to:
    ports:    default/registered TCP port(s)
    category: logical grouping (maintainability/organization only)
    fp:       the fingerprint service name used in the detection engine
              when it differs from `name` (else None -> same as name)

The `fp` link lets the engine use a port as a *candidate hint* (which
fingerprints to try first). A port hint never identifies a service on
its own; identification always requires a matching response.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Category labels (organization only; do not affect detection).
WEB = "web"
REMOTE = "remote-access"
FILE = "file-transfer"
MAIL = "mail"
DB = "database"
DIR = "directory"
NAME = "name-resolution"
MSG = "messaging"
MON = "monitoring"
AUTH = "authentication"
NET = "network-management"
VCS = "version-control"
PROXY = "proxy"
INFRA = "infrastructure"
MEDIA = "media"
IOT = "iot"


@dataclass(frozen=True)
class CommonService:
    """One catalog entry."""
    name: str
    ports: Tuple[int, ...]
    category: str
    transport: str = "tcp"
    fp: Optional[str] = None

    def fingerprint_service(self) -> str:
        """Fingerprint-engine service name this entry maps to."""
        return self.fp or self.name


# (name, ports, category, fp) - fp omitted when equal to name.
# Curated common-service dataset (~256 services across categories).
_CATALOG = [
    # ---- Web ----
    ("http", (80,), WEB, None), ("https", (443,), WEB, "http"),
    ("http-alt", (8080,), WEB, "http"), ("https-alt", (8443,), WEB, "http"),
    ("http-alt2", (8000,), WEB, "http"), ("http-alt3", (8888,), WEB, "http"),
    ("http-alt4", (8081,), WEB, "http"), ("nginx-status", (8181,), WEB, "http"),
    ("tomcat", (8005, 8009), WEB, "http"), ("webcache", (8123,), WEB, "http"),
    ("cpanel", (2082, 2083), WEB, "http"), ("whm", (2086, 2087), WEB, "http"),
    ("webmin", (10000,), WEB, "http"), ("couchdb", (5984,), WEB, "http"),
    ("kibana", (5601,), WEB, "http"), ("grafana", (3000,), WEB, "http"),
    ("prometheus", (9090,), MON, "http"), ("jenkins", (8083,), WEB, "http"),
    ("php-fpm", (9000,), WEB, None), ("uwsgi", (3031,), WEB, None),

    # ---- Remote access / graphical ----
    ("ssh", (22,), REMOTE, None), ("telnet", (23,), REMOTE, None),
    ("rlogin", (513,), REMOTE, None), ("rsh", (514,), REMOTE, None),
    ("rexec", (512,), REMOTE, None),
    ("ms-wbt-server", (3389,), REMOTE, None), ("rdp", (3389,), REMOTE,
                                              "ms-wbt-server"),
    ("vnc", (5900, 5901, 5902), REMOTE, None),
    ("vnc-http", (5800,), REMOTE, "http"), ("X11", (6000, 6001), REMOTE, None),
    ("pcanywhere", (5631, 5632), REMOTE, None),
    ("teamviewer", (5938,), REMOTE, None), ("anydesk", (7070,), REMOTE, None),
    ("winrm", (5985, 5986), REMOTE, "http"), ("telnets", (992,), REMOTE, None),

    # ---- File transfer / sharing ----
    ("ftp", (21,), FILE, None), ("ftp-data", (20,), FILE, "ftp"),
    ("ftps", (990,), FILE, "ftp"), ("sftp", (115,), FILE, None),
    ("tftp", (69,), FILE, None, "udp"),
    ("smb", (445,), FILE, None), ("microsoft-ds", (445,), FILE, "smb"),
    ("netbios-ssn", (139,), FILE, None), ("netbios-ns", (137,), FILE, None,
                                          "udp"),
    ("netbios-dgm", (138,), FILE, None, "udp"),
    ("afp", (548,), FILE, None), ("nfs", (2049,), FILE, None),
    ("rsync", (873,), FILE, None), ("rpcbind", (111,), FILE, None),
    ("webdav", (2078,), FILE, "http"), ("svn", (3690,), VCS, "svnserve"),

    # ---- Mail ----
    ("smtp", (25,), MAIL, None), ("smtps", (465,), MAIL, "smtp"),
    ("submission", (587,), MAIL, "smtp"), ("pop3", (110,), MAIL, None),
    ("pop3s", (995,), MAIL, "pop3"), ("imap", (143,), MAIL, None),
    ("imaps", (993,), MAIL, "imap"), ("nntp", (119,), MAIL, None),
    ("nntps", (563,), MAIL, "nntp"), ("lmtp", (24,), MAIL, "smtp"),
    ("managesieve", (4190,), MAIL, None),

    # ---- Databases ----
    ("mysql", (3306,), DB, None), ("mariadb", (3306,), DB, "mysql"),
    ("postgresql", (5432,), DB, None), ("ms-sql-s", (1433,), DB, None),
    ("ms-sql-m", (1434,), DB, "ms-sql-s"),
    ("oracle-tns", (1521,), DB, None), ("redis", (6379,), DB, None),
    ("mongodb", (27017, 27018), DB, None),
    ("memcached", (11211,), DB, None), ("cassandra", (9042,), DB, None),
    ("db2", (50000,), DB, None), ("couchdb-db", (5986,), DB, "http"),
    ("elasticsearch", (9200, 9300), DB, None),
    ("influxdb", (8086,), DB, "http"), ("neo4j", (7687,), DB, None),
    ("clickhouse", (8123, 9001), DB, None),
    ("cockroachdb", (26257,), DB, "postgresql"),
    ("rethinkdb", (28015,), DB, None), ("firebird", (3050,), DB, None),
    ("informix", (1526,), DB, None), ("sybase", (5000,), DB, None),

    # ---- Directory / authentication ----
    ("ldap", (389,), DIR, None), ("ldaps", (636,), DIR, "ldap"),
    ("globalcat", (3268, 3269), DIR, "ldap"),
    ("kerberos", (88,), AUTH, None), ("kpasswd", (464,), AUTH, None),
    ("radius", (1812, 1813), AUTH, None, "udp"),
    ("tacacs", (49,), AUTH, None), ("ident", (113,), AUTH, None),
    ("auth", (113,), AUTH, "ident"), ("nnp", (218,), AUTH, None),

    # ---- Name resolution ----
    ("domain", (53,), NAME, None), ("dns-tcp", (53,), NAME, "domain"),
    ("mdns", (5353,), NAME, None, "udp"),
    ("llmnr", (5355,), NAME, None, "udp"), ("whois", (43,), NAME, None),
    ("rwhois", (4321,), NAME, None), ("dnsix", (195,), NAME, None),

    # ---- Messaging / realtime ----
    ("irc", (6667,), MSG, None), ("ircs", (6697,), MSG, "irc"),
    ("xmpp-client", (5222,), MSG, "xmpp"),
    ("xmpp-server", (5269,), MSG, "xmpp"), ("sip", (5060,), MSG, None),
    ("sips", (5061,), MSG, "sip"),
    ("mqtt", (1883,), IOT, None), ("mqtts", (8883,), IOT, "mqtt"),
    ("amqp", (5672,), MSG, None), ("amqps", (5671,), MSG, "amqp"),
    ("stomp", (61613,), MSG, None), ("kafka", (9092,), MSG, None),
    ("nats", (4222,), MSG, None), ("zeromq", (5555,), MSG, None),
    ("rtmp", (1935,), MEDIA, None), ("rtsp", (554,), MEDIA, None),
    ("sip-tls", (5062,), MSG, "sip"),

    # ---- Monitoring / network management ----
    ("snmp", (161,), MON, None, "udp"),
    ("snmptrap", (162,), MON, None, "udp"),
    ("ntp", (123,), NET, None, "udp"), ("syslog", (514,), MON, None, "udp"),
    ("nrpe", (5666,), MON, None), ("zabbix-agent", (10050,), MON, None),
    ("zabbix-server", (10051,), MON, None), ("collectd", (25826,), MON, None,
                                             "udp"),
    ("graphite", (2003,), MON, None), ("statsd", (8125,), MON, None, "udp"),
    ("netflow", (2055,), NET, None, "udp"), ("ipmi", (623,), NET, None,
                                             "udp"),
    ("bgp", (179,), NET, None), ("ospf", (89,), NET, None),
    ("snmp-tls", (10161,), MON, None), ("cacti", (161,), MON, "snmp"),

    # ---- Infrastructure / RPC / discovery ----
    ("upnp", (1900,), INFRA, None, "udp"),
    ("ssdp", (1900,), INFRA, "upnp", "udp"), ("msrpc", (135,), INFRA, None),
    ("epmap", (135,), INFRA, "msrpc"), ("wsdapi", (5357,), INFRA, "http"),
    ("printer", (515,), INFRA, None), ("ipp", (631,), INFRA, None),
    ("jetdirect", (9100,), INFRA, None), ("finger", (79,), INFRA, None),
    ("daytime", (13,), INFRA, None), ("echo", (7,), INFRA, None),
    ("discard", (9,), INFRA, None), ("chargen", (19,), INFRA, None),
    ("qotd", (17,), INFRA, None), ("time", (37,), INFRA, None),
    ("systat", (11,), INFRA, None), ("netstat", (15,), INFRA, None),
    ("bootps", (67,), INFRA, None, "udp"),
    ("bootpc", (68,), INFRA, None, "udp"), ("gopher", (70,), INFRA, None),

    # ---- Proxy / caching ----
    ("http-proxy", (8080, 3128), PROXY, None),
    ("squid", (3128,), PROXY, "http-proxy"), ("socks", (1080,), PROXY, None),
    ("socks5", (1080,), PROXY, "socks"), ("privoxy", (8118,), PROXY, "http"),
    ("polipo", (8123,), PROXY, "http"), ("tor-socks", (9050,), PROXY,
                                         "socks"),
    ("haproxy-stats", (1936,), PROXY, "http"),

    # ---- Version control / dev ----
    ("git", (9418,), VCS, None), ("svnserve", (3690,), VCS, None),
    ("cvspserver", (2401,), VCS, None), ("gitlab", (8929,), VCS, "http"),
    ("gerrit", (29418,), VCS, "ssh"),

    # ---- Containers / orchestration / infra services ----
    ("docker", (2375, 2376), INFRA, None),
    ("docker-registry", (5000,), INFRA, "http"),
    ("kubernetes-api", (6443,), INFRA, "http"),
    ("etcd", (2379, 2380), INFRA, None),
    ("consul", (8500,), INFRA, "http"),
    ("zookeeper", (2181,), INFRA, None), ("nomad", (4646,), INFRA, "http"),
    ("vault", (8200,), INFRA, "http"), ("rabbitmq-mgmt", (15672,), MSG,
                                        "http"),

    # ---- Remote admin / VPN / tunneling ----
    ("openvpn", (1194,), NET, None, "udp"),
    ("wireguard", (51820,), NET, None, "udp"),
    ("pptp", (1723,), NET, None), ("l2tp", (1701,), NET, None, "udp"),
    ("isakmp", (500,), NET, None, "udp"),

    # ---- Windows / enterprise ----
    ("ms-sql-browser", (1434,), DB, "ms-sql-s", "udp"),
    ("wins", (1512,), NAME, None), ("dhcp-failover", (647,), INFRA, None),
    ("ms-lsa", (1029,), INFRA, "msrpc"),
    ("ms-exchange", (135,), MAIL, "msrpc"),
    ("winrm-https", (5986,), REMOTE, "http"),

    # ---- Media / streaming / voip ----
    ("h323", (1720,), MEDIA, None), ("mgcp", (2427,), MEDIA, None, "udp"),
    ("iax2", (4569,), MEDIA, None, "udp"), ("asterisk", (5038,), MEDIA, None),
    ("shoutcast", (8000,), MEDIA, "http"), ("icecast", (8000,), MEDIA,
                                            "http"),
    ("plex", (32400,), MEDIA, "http"), ("airplay", (7000,), MEDIA, "http"),

    # ---- IoT / industrial ----
    ("coap", (5683,), IOT, None, "udp"), ("modbus", (502,), IOT, None),
    ("bacnet", (47808,), IOT, None, "udp"), ("dnp3", (20000,), IOT, None),
    ("ethernet-ip", (44818,), IOT, None), ("s7", (102,), IOT, None),
    ("niagara-fox", (1911,), IOT, None), ("knx", (3671,), IOT, None, "udp"),

    # ---- Game / misc app servers ----
    ("minecraft", (25565,), MEDIA, None),
    ("teamspeak", (9987,), MEDIA, None, "udp"),
    ("steam", (27015,), MEDIA, None), ("murmur", (64738,), MEDIA, None),
    ("rcon", (25575,), MEDIA, None),

    # ---- Additional common services ----
    ("submissions", (465,), MAIL, "smtp"), ("nntp-tls", (563,), MAIL, "nntp"),
    ("sieve", (2000,), MAIL, None), ("ldap-admin", (389,), DIR, "ldap"),
    ("git-http", (443,), VCS, "http"), ("mysqlx", (33060,), DB, None),
    ("pgbouncer", (6432,), DB, "postgresql"),
    ("redis-sentinel", (26379,), DB, "redis"),
    ("memcached-udp", (11211,), DB, None, "udp"),
    ("elastic-transport", (9300,), DB, "elasticsearch"),
    ("solr", (8983,), DB, "http"), ("splunk", (8089,), MON, "http"),
    ("splunkweb", (8000,), MON, "http"), ("nagios", (5667,), MON, None),
    ("munin", (4949,), MON, None), ("cups", (631,), INFRA, "ipp"),
    ("avahi", (5353,), NAME, "mdns", "udp"),
    ("dropbox-lan", (17500,), INFRA, None, "udp"),
    ("apple-remote", (3283,), REMOTE, None, "udp"),
    ("distcc", (3632,), INFRA, None), ("ganglia", (8649,), MON, None),
    ("beanstalkd", (11300,), MSG, None), ("gearman", (4730,), MSG, None),
    ("riak", (8087,), DB, None), ("aerospike", (3000,), DB, None),
    ("voltdb", (21212,), DB, None), ("hbase", (16010,), DB, "http"),
    ("hadoop-namenode", (9870,), DB, "http"),
    ("spark", (7077,), INFRA, None), ("mesos", (5050,), INFRA, "http"),
    ("flink", (8081,), INFRA, "http"), ("airflow", (8080,), INFRA, "http"),
    ("sonarqube", (9000,), INFRA, "http"), ("nexus", (8081,), INFRA, "http"),
    ("artifactory", (8082,), INFRA, "http"),
    ("portainer", (9443,), INFRA, "http"),
    ("cockpit", (9090,), REMOTE, "http"), ("proxmox", (8006,), REMOTE,
                                           "http"),
    ("esxi", (902,), REMOTE, None), ("vcenter", (443,), REMOTE, "http"),
    ("ilo", (17988,), REMOTE, "http"), ("idrac", (443,), REMOTE, "http"),
    (" upsmon", (3493,), MON, None), ("nut", (3493,), MON, None),
    ("smux", (199,), NET, None), ("bfd", (3784,), NET, None, "udp"),
    ("ptp", (319, 320), NET, None, "udp"),
    ("radmin", (4899,), REMOTE, None), ("dameware", (6129,), REMOTE, None),
    ("sophos", (8443,), NET, "http"), ("checkpoint", (18190,), NET, None),
    ("fortinet", (541,), NET, None), ("openvpn-tcp", (443,), NET, "http"),
]


def _build(catalog) -> List[CommonService]:
    services = []
    for entry in catalog:
        name, ports, category = entry[0], entry[1], entry[2]
        fp = entry[3] if len(entry) > 3 else None
        transport = entry[4] if len(entry) > 4 else "tcp"
        services.append(
            CommonService(name=name.strip(), ports=tuple(ports),
                          category=category, transport=transport, fp=fp))
    return services


COMMON_SERVICES: List[CommonService] = _build(_CATALOG)


def tcp_port_hints() -> Dict[int, Tuple[str, ...]]:
    """
    Builds {tcp_port: (fingerprint_service, ...)} for candidate selection.

    Only TCP entries with a valid port contribute. Fingerprint service
    names are de-duplicated per port, preserving insertion order.
    """
    hints: Dict[int, list] = {}
    for service in COMMON_SERVICES:
        if service.transport != "tcp":
            continue
        fp_name = service.fingerprint_service()
        for port in service.ports:
            if not 1 <= port <= 65535:
                continue
            bucket = hints.setdefault(port, [])
            if fp_name not in bucket:
                bucket.append(fp_name)
    return {port: tuple(names) for port, names in hints.items()}


def services_by_category() -> Dict[str, List[str]]:
    """Groups service names by category (organization/debugging)."""
    grouped: Dict[str, list] = {}
    for service in COMMON_SERVICES:
        grouped.setdefault(service.category, []).append(service.name)
    return grouped
