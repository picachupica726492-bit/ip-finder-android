"""
core.py - Pure-Python engine for the mobile IP Finder.

Android apps cannot run desktop command-line tools (nmap, dig, amass, ...)
without root, so each of the 15 tools is re-implemented here using only the
Python standard library:

    ping          -> TCP reachability test (ICMP needs root on Android)
    nslookup      -> system resolver
    dig           -> DNS-over-HTTPS (Cloudflare): A, AAAA
    host          -> DNS-over-HTTPS (Google): A, AAAA (cross-check)
    whois         -> WHOIS over TCP port 43
    dnsrecon      -> DNS record enumeration (A/AAAA/MX/NS/TXT/SOA, SPF IPs)
    dnsenum       -> subdomain brute force with a built-in wordlist
    fierce        -> reverse-DNS scan of neighbouring IPs
    theHarvester  -> crt.sh certificate transparency logs
    amass         -> AlienVault OTX passive DNS
    subfinder     -> HackerTarget host search
    assetfinder   -> CertSpotter certificate transparency API
    httpx         -> HTTP(S) probe (status, title, server, connected IP)
    whatweb       -> technology / CDN fingerprinting
    nmap          -> TCP connect scan of common ports

Use only on domains you own or have written permission to test.
"""

import concurrent.futures
import http.client
import ipaddress
import json
import random
import re
import socket
import ssl
import string
import threading
import time
import urllib.parse
import urllib.request

try:  # certifi gives Python a CA bundle on Android
    import certifi
    _CTX = ssl.create_default_context(cafile=certifi.where())
except Exception:  # noqa: BLE001
    _CTX = ssl.create_default_context()

UA = "Mozilla/5.0 (Linux; Android 13) IPFinder/1.0"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I
)
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
IPV6_RE = re.compile(r"(?<![\w:.])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")

TOOL_ORDER = ["ping", "nslookup", "dig", "host", "whois", "dnsrecon", "dnsenum", "fierce",
              "theHarvester", "amass", "subfinder", "assetfinder", "httpx", "whatweb", "nmap"]

TOOL_INFO = {
    "ping": "TCP reachability (443/80)",
    "nslookup": "System DNS resolver",
    "dig": "DNS-over-HTTPS (Cloudflare)",
    "host": "DNS-over-HTTPS (Google)",
    "whois": "WHOIS (port 43): nameservers",
    "dnsrecon": "A/AAAA/MX/NS/TXT/SOA records",
    "dnsenum": "Subdomain brute force",
    "fierce": "Reverse DNS of nearby IPs",
    "theHarvester": "crt.sh certificate logs",
    "amass": "AlienVault OTX passive DNS",
    "subfinder": "HackerTarget host search",
    "assetfinder": "CertSpotter certificate API",
    "httpx": "HTTP/HTTPS probe",
    "whatweb": "Tech and CDN fingerprint",
    "nmap": "TCP connect scan (common ports)",
}

WORDLIST = """www mail ftp smtp pop pop3 imap webmail ns1 ns2 ns3 dns mx mx1 mx2 admin portal vpn
remote api dev test staging stage beta demo app apps blog shop store cdn static assets img images
media files download downloads support help docs wiki git gitlab jenkins ci db sql mysql ssh secure
login auth sso cpanel whm direct m mobile intranet extranet cloud autodiscover autoconfig owa
exchange status monitor grafana kibana crm erp forum community news old new backup panel
dashboard cms web web1 web2 server host origin direct-connect""".split()

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def is_public(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str.split("%")[0])
    except ValueError:
        return False
    return not (ip.is_loopback or ip.is_private or ip.is_multicast or ip.is_unspecified
                or ip.is_reserved or ip.is_link_local)


def extract_ips(text):
    found = set()
    for m in IPV4_RE.findall(text) + IPV6_RE.findall(text):
        if is_public(m):
            found.add(str(ipaddress.ip_address(m)))
    return found


def registrable(domain):
    """Best-effort registrable domain (handles common co.uk-style suffixes)."""
    p = domain.lower().strip(".").split(".")
    if len(p) >= 3 and len(p[-1]) == 2 and p[-2] in {"co", "com", "org", "net", "gov", "edu", "ac"}:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def extract_hosts(text, scope):
    pattern = re.compile(r"(?<![\w.-])((?:[a-z0-9_-]+\.)*" + re.escape(scope) + r")(?![\w-])", re.I)
    return {h.lower().strip(".") for h in pattern.findall(text)
            if not h.startswith("*") and "@" not in h}


def resolve(host):
    """Resolve a hostname with the system resolver; returns public IPs only."""
    out = []
    try:
        for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
            ip = info[4][0]
            if ip not in out and is_public(ip):
                out.append(ip)
    except (OSError, UnicodeError):
        pass
    return out


def http_get(url, timeout=20, headers=None):
    h = {"User-Agent": UA, "Accept": "application/json,text/plain,*/*"}
    h.update(headers or {})
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as resp:
        return resp.read(5_000_000).decode("utf-8", "replace")


_TYPES = {"A": 1, "AAAA": 28, "NS": 2, "MX": 15, "TXT": 16, "SOA": 6, "CNAME": 5}


def doh(name, rtype, provider="cloudflare", timeout=12):
    """DNS-over-HTTPS query; returns a list of record data strings."""
    q = urllib.parse.quote(name)
    if provider == "cloudflare":
        url = f"https://cloudflare-dns.com/dns-query?name={q}&type={rtype}"
        hdr = {"Accept": "application/dns-json"}
    else:
        url = f"https://dns.google/resolve?name={q}&type={rtype}"
        hdr = {}
    data = json.loads(http_get(url, timeout, hdr))
    return [a["data"].strip().strip('"') for a in data.get("Answer", [])
            if a.get("type") == _TYPES[rtype]]


def new_result(name, kind):
    return {"tool": name, "kind": kind, "status": "ok", "ips": set(), "related_ips": set(),
            "hosts": set(), "related_hosts": set(), "notes": set(), "info": ""}


def resolve_many(hosts, stop, workers=20):
    out = {}
    if not hosts:
        return out

    def one(h):
        return h, ([] if stop.is_set() else resolve(h))

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for h, ips in ex.map(one, sorted(hosts)):
            if ips:
                out[h] = sorted(ips)
    return out


# --------------------------------------------------------------------------
# HTTP probe (shared by httpx and whatweb)
# --------------------------------------------------------------------------
def _do_probe(domain, timeout):
    last_err = ""
    for scheme in ("https", "http"):
        for verify in ((True, False) if scheme == "https" else (True,)):
            conn = None
            try:
                if scheme == "https":
                    c = _CTX if verify else ssl._create_unverified_context()  # noqa: SLF001
                    conn = http.client.HTTPSConnection(domain, timeout=timeout, context=c)
                else:
                    conn = http.client.HTTPConnection(domain, timeout=timeout)
                conn.connect()
                peer = conn.sock.getpeername()[0]  # read before the response closes the socket
                conn.request("GET", "/", headers={"User-Agent": UA, "Accept": "*/*",
                                                  "Connection": "close"})
                resp = conn.getresponse()
                body = resp.read(200_000).decode("utf-8", "replace")
                title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                return {"scheme": scheme, "status": resp.status, "peer": peer,
                        "headers": {k.lower(): v for k, v in resp.getheaders()},
                        "body": body, "verified": verify,
                        "title": re.sub(r"\s+", " ", title.group(1)).strip()[:80] if title else ""}
            except ssl.SSLCertVerificationError as e:
                last_err = f"certificate error: {e.verify_message}"
                continue  # retry unverified so we can still learn the IP
            except Exception as e:  # noqa: BLE001
                last_err = f"{type(e).__name__}: {e}"
                break
            finally:
                if conn is not None:
                    conn.close()
    return {"error": last_err or "no response"}


def _probe(domain, ctx):
    with ctx["probe_lock"]:
        if ctx.get("probe") is None:
            ctx["probe"] = _do_probe(domain, ctx["timeout"])
        return ctx["probe"]


def _fingerprint(p):
    techs, cdns = [], set()
    h, body = p["headers"], p["body"]
    low = body.lower()
    if h.get("server"):
        techs.append(f"Server={h['server']}")
    if h.get("x-powered-by"):
        techs.append(f"X-Powered-By={h['x-powered-by']}")
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        techs.append(f"Generator={gen.group(1)[:40]}")
    for marker, label in [("wp-content", "WordPress"), ("/sites/default/", "Drupal"),
                          ("joomla", "Joomla"), ("cdn.shopify.com", "Shopify"),
                          ("wixstatic.com", "Wix"), ("squarespace", "Squarespace"),
                          ("jquery", "jQuery"), ("bootstrap", "Bootstrap"),
                          ("react", "React"), ("googletagmanager", "GoogleTagManager")]:
        if marker in low:
            techs.append(label)
    blob = " ".join(f"{k}:{v}" for k, v in h.items()).lower()
    if "cf-ray" in h or "cloudflare" in blob:
        cdns.add("Cloudflare")
    if "x-amz-cf-id" in h or "cloudfront" in blob:
        cdns.add("CloudFront")
    if "akamai" in blob:
        cdns.add("Akamai")
    if "fastly" in blob:
        cdns.add("Fastly")
    if "x-sucuri-id" in h:
        cdns.add("Sucuri")
    if "x-iinfo" in h or "incapsula" in blob:
        cdns.add("Imperva")
    return techs, cdns


# --------------------------------------------------------------------------
# The 15 tools
# --------------------------------------------------------------------------
def tool_ping(domain, ctx):
    r = new_result("ping", "direct")
    ips = resolve(domain)
    if not ips:
        r["status"] = "no_resolution"
        return r
    lat = []
    for ip in ips[:4]:
        for port in (443, 80):
            t = time.time()
            try:
                with socket.create_connection((ip, port), timeout=3):
                    lat.append(f"{ip}:{port} {int((time.time() - t) * 1000)}ms")
                    break
            except OSError:
                continue
    r["ips"] = set(ips)
    r["info"] = "TCP: " + ("; ".join(lat) if lat else "no reply on 443/80")
    return r


def tool_nslookup(domain, ctx):
    r = new_result("nslookup", "direct")
    ips = resolve(domain)
    if not ips:
        r["status"] = "no_records"
    r["ips"] = set(ips)
    r["info"] = ", ".join(ips)
    return r


def tool_dig(domain, ctx):
    r = new_result("dig", "direct")
    parts = []
    for rt in ("A", "AAAA"):
        data = doh(domain, rt, "cloudflare", ctx["timeout"])
        r["ips"] |= extract_ips(" ".join(data))
        parts.append(f"{rt}: {', '.join(data) or '-'}")
    if not r["ips"]:
        r["status"] = "no_records"
    r["info"] = " | ".join(parts)
    return r


def tool_host(domain, ctx):
    r = new_result("host", "direct")
    parts = []
    for rt in ("A", "AAAA", "CNAME"):
        data = doh(domain, rt, "google", ctx["timeout"])
        if rt != "CNAME":
            r["ips"] |= extract_ips(" ".join(data))
        parts.append(f"{rt}: {', '.join(data) or '-'}")
    if not r["ips"]:
        r["status"] = "no_records"
    r["info"] = " | ".join(parts)
    return r


def _whois(server, query, timeout):
    chunks = []
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode())
        while True:
            try:
                b = s.recv(4096)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
    return b"".join(chunks).decode("utf-8", "replace")


def tool_whois(domain, ctx):
    r = new_result("whois", "discovery")
    scope = registrable(domain)
    tld = scope.rsplit(".", 1)[-1]
    iana = _whois("whois.iana.org", tld, ctx["timeout"])
    m = re.search(r"^whois:\s*(\S+)", iana, re.M | re.I)
    if not m:
        r["status"] = "no_whois_server"
        return r
    text = _whois(m.group(1), scope, ctx["timeout"])
    for ns in re.findall(r"^\s*Name Server:\s*(\S+)", text, re.M | re.I):
        r["related_hosts"].add(ns.lower().strip("."))
    r["related_ips"] = extract_ips(text)
    reg = re.search(r"^\s*Registrar:\s*(.+)$", text, re.M | re.I)
    r["info"] = f"server {m.group(1)}; registrar {reg.group(1).strip() if reg else '-'}; " \
                f"{len(r['related_hosts'])} nameserver(s)"
    return r


def tool_dnsrecon(domain, ctx):
    r = new_result("dnsrecon", "discovery")
    scope = registrable(domain)
    counts = []
    for rt in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        try:
            data = doh(scope, rt, "cloudflare", ctx["timeout"])
        except Exception:  # noqa: BLE001
            data = []
        counts.append(f"{rt}={len(data)}")
        if rt in ("A", "AAAA"):
            r["related_ips"] |= extract_ips(" ".join(data))
        elif rt in ("MX", "NS"):
            for d in data:
                r["related_hosts"].add(d.split()[-1].lower().strip("."))
        elif rt == "TXT":
            # SPF records often list real mail/origin server IPs
            r["related_ips"] |= extract_ips(" ".join(re.findall(r"ip[46]:([^\s]+)", " ".join(data))))
    r["info"] = ", ".join(counts)
    return r


def tool_dnsenum(domain, ctx):
    r = new_result("dnsenum", "discovery")
    rnd = "zz-" + "".join(random.choices(string.ascii_lowercase, k=12))
    if resolve(f"{rnd}.{domain}"):
        r["status"] = "wildcard_dns (skipped)"
        return r
    t_end = time.time() + ctx["tool_timeout"]

    def look(w):
        if ctx["stop"].is_set() or time.time() > t_end:
            return None
        h = f"{w}.{domain}"
        ips = resolve(h)
        return (h, ips) if ips else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        for res in ex.map(look, WORDLIST):
            if res:
                r["hosts"].add(res[0])
                r["related_ips"] |= set(res[1])
    r["info"] = f"{len(WORDLIST)} names tried, {len(r['hosts'])} found"
    return r


def tool_fierce(domain, ctx):
    r = new_result("fierce", "discovery")
    scope = registrable(domain)
    base_ips = [i for i in resolve(domain) if "." in i][:2]
    if not base_ips:
        r["status"] = "no_ipv4"
        return r
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=20)
    futs = {}
    for ip in base_ips:
        base = ipaddress.ip_address(ip)
        for off in range(-5, 6):
            if off == 0:
                continue
            try:
                neighbour = str(base + off)
            except ValueError:
                continue
            futs[ex.submit(socket.gethostbyaddr, neighbour)] = neighbour
    done, _ = concurrent.futures.wait(futs, timeout=ctx["tool_timeout"])
    for f in done:
        try:
            name = f.result()[0].lower().strip(".")
        except Exception:  # noqa: BLE001
            continue
        if name == scope or name.endswith("." + scope):
            r["hosts"].add(name)
            r["related_ips"].add(futs[f])
    ex.shutdown(wait=False, cancel_futures=True)
    r["info"] = f"{len(futs)} neighbouring IPs checked, {len(r['hosts'])} matching name(s)"
    return r


def tool_theharvester(domain, ctx):
    r = new_result("theHarvester", "discovery")
    scope = registrable(domain)
    text = http_get(f"https://crt.sh/?q=%25.{scope}&output=json", max(ctx["timeout"], 40))
    for row in json.loads(text):
        r["hosts"] |= extract_hosts(row.get("name_value", ""), scope)
    r["info"] = f"{len(r['hosts'])} hostname(s) from certificates"
    return r


def tool_amass(domain, ctx):
    r = new_result("amass", "discovery")
    scope = registrable(domain)
    data = json.loads(http_get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{scope}/passive_dns", ctx["timeout"]))
    for row in data.get("passive_dns", []):
        r["hosts"] |= extract_hosts(row.get("hostname", ""), scope)
        if row.get("record_type") in ("A", "AAAA"):
            r["related_ips"] |= extract_ips(row.get("address", ""))
    r["info"] = f"{len(r['hosts'])} hostname(s), {len(r['related_ips'])} IP(s) from passive DNS"
    return r


def tool_subfinder(domain, ctx):
    r = new_result("subfinder", "discovery")
    scope = registrable(domain)
    text = http_get(f"https://api.hackertarget.com/hostsearch/?q={scope}", ctx["timeout"])
    if text.lower().startswith(("error", "api count exceeded")):
        r["status"] = "api_limit_or_error"
        r["info"] = text.strip()[:80]
        return r
    for line in text.splitlines():
        host, _, ip = line.partition(",")
        r["hosts"] |= extract_hosts(host, scope)
        r["related_ips"] |= extract_ips(ip)
    r["info"] = f"{len(r['hosts'])} host(s)"
    return r


def tool_assetfinder(domain, ctx):
    r = new_result("assetfinder", "discovery")
    scope = registrable(domain)
    text = http_get(f"https://api.certspotter.com/v1/issuances?domain={scope}"
                    f"&include_subdomains=true&expand=dns_names", ctx["timeout"])
    data = json.loads(text)
    if isinstance(data, dict):  # rate-limit message
        r["status"] = "api_limit_or_error"
        r["info"] = str(data.get("message", ""))[:80]
        return r
    for row in data:
        for name in row.get("dns_names", []):
            r["hosts"] |= extract_hosts(name, scope)
    r["info"] = f"{len(r['hosts'])} hostname(s) from certificates"
    return r


def tool_httpx(domain, ctx):
    r = new_result("httpx", "direct")
    p = _probe(domain, ctx)
    if "error" in p:
        r["status"] = "no_response"
        r["info"] = p["error"][:100]
        return r
    r["ips"] = extract_ips(p["peer"])
    r["info"] = (f"{p['scheme']}://{domain} [{p['status']}] "
                 f"[{p['title'] or 'no title'}] [{p['headers'].get('server', '-')}]")
    return r


def tool_whatweb(domain, ctx):
    r = new_result("whatweb", "direct")
    p = _probe(domain, ctx)
    if "error" in p:
        r["status"] = "no_response"
        r["info"] = p["error"][:100]
        return r
    techs, cdns = _fingerprint(p)
    r["ips"] = extract_ips(p["peer"])
    for c in cdns:
        r["notes"].add(f"{c} detected: these IPs probably belong to the CDN, not the origin server")
    r["info"] = ", ".join(techs + sorted(f"CDN={c}" for c in cdns)) or "nothing identified"
    return r


def tool_nmap(domain, ctx):
    r = new_result("nmap", "direct")
    ips = resolve(domain)[:4]
    if not ips:
        r["status"] = "no_resolution"
        return r
    t_end = time.time() + ctx["tool_timeout"]

    def check(args):
        ip, port = args
        if ctx["stop"].is_set() or time.time() > t_end:
            return None
        try:
            with socket.create_connection((ip, port), timeout=2):
                return ip, port
        except OSError:
            return None

    open_ports = {}
    jobs = [(ip, p) for ip in ips for p in COMMON_PORTS]
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        for res in ex.map(check, jobs):
            if res:
                open_ports.setdefault(res[0], []).append(res[1])
    r["ips"] = set(open_ports)
    if not open_ports:
        r["status"] = "host_down_or_filtered"
    r["info"] = "; ".join(f"{ip}: {','.join(map(str, sorted(p)))}" for ip, p in open_ports.items()) \
        or "no open ports among the common ones"
    return r


TOOLS = {
    "ping": tool_ping, "nslookup": tool_nslookup, "dig": tool_dig, "host": tool_host,
    "whois": tool_whois, "dnsrecon": tool_dnsrecon, "dnsenum": tool_dnsenum,
    "fierce": tool_fierce, "theHarvester": tool_theharvester, "amass": tool_amass,
    "subfinder": tool_subfinder, "assetfinder": tool_assetfinder, "httpx": tool_httpx,
    "whatweb": tool_whatweb, "nmap": tool_nmap,
}


# --------------------------------------------------------------------------
# Scan runner and result aggregation
# --------------------------------------------------------------------------
def run_scan(domain, tool_names, stop_event, emit, workers=6, timeout=20, tool_timeout=60):
    """Run the selected tools. emit(event, payload) is called from worker threads.

    Events: "log" (str), "tool_done" (result dict), "stage" (str), "final" (dict).
    """
    ctx = {"timeout": timeout, "tool_timeout": tool_timeout, "stop": stop_event,
           "probe": None, "probe_lock": threading.Lock()}
    scope = registrable(domain)
    selected = [n for n in TOOL_ORDER if n in tool_names]

    def run_one(name):
        r = new_result(name, "direct")
        if stop_event.is_set():
            r["status"] = "cancelled"
            return r
        emit("log", f"[*] {name}: started")
        try:
            r = TOOLS[name](domain, ctx)
        except Exception as e:  # noqa: BLE001
            r["status"] = f"error: {type(e).__name__}: {str(e)[:70]}"
        if stop_event.is_set() and r["status"] == "ok":
            r["status"] = "cancelled (partial)"
        return r

    hosts, related_hosts = set(), set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(run_one, n) for n in selected]
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            hosts |= r["hosts"]
            related_hosts |= r["related_hosts"]
            emit("tool_done", r)

    hosts.discard(domain)
    hosts.discard(scope)
    hosts = set(sorted(hosts)[:200])
    related_hosts -= hosts

    subdomains, related_map = {}, {}
    if hosts and not stop_event.is_set():
        emit("stage", f"Resolving {len(hosts)} subdomain(s)...")
        subdomains = resolve_many(hosts, stop_event)
    if related_hosts and not stop_event.is_set():
        emit("stage", f"Resolving {len(related_hosts)} nameserver/mail host(s)...")
        related_map = resolve_many(related_hosts, stop_event)

    emit("final", {"subdomains": subdomains, "related_map": related_map,
                   "cancelled": stop_event.is_set()})


class Aggregator:
    """Collects tool results and builds the text views and the report."""

    def __init__(self, domain=""):
        self.domain = domain
        self.results = {}
        self.main_ips = {}          # ip -> set(tools)
        self.related_tool_ips = set()
        self.notes = set()
        self.subdomains = {}        # host -> [ips]
        self.related_map = {}       # nameserver/mail host -> [ips]

    def add(self, r):
        self.results[r["tool"]] = r
        for ip in r["ips"]:
            self.main_ips.setdefault(ip, set()).add(r["tool"])
        self.related_tool_ips |= r["related_ips"]
        self.notes |= r["notes"]

    def set_resolved(self, subdomains, related_map):
        self.subdomains = subdomains
        self.related_map = related_map

    def related_ips(self):
        ips = set(self.related_tool_ips)
        for addrs in list(self.subdomains.values()) + list(self.related_map.values()):
            ips |= set(addrs)
        return sorted(ips - set(self.main_ips))

    def to_dict(self):
        return {
            "domain": self.domain,
            "main_ips": {ip: sorted(t) for ip, t in self.main_ips.items()},
            "subdomains": self.subdomains,
            "nameserver_and_mail_hosts": self.related_map,
            "related_ips": self.related_ips(),
            "notes": sorted(self.notes),
            "tool_status": {n: r["status"] for n, r in self.results.items()},
        }

    def report(self):
        lines = [f"IP Finder report: {self.domain}", ""]
        lines.append("Main IPs:")
        for ip, t in sorted(self.main_ips.items(), key=lambda x: (-len(x[1]), x[0])):
            lines.append(f"  {ip}  ({len(t)} tools: {', '.join(sorted(t))})")
        if not self.main_ips:
            lines.append("  none found")
        if self.subdomains:
            lines += ["", "Subdomains:"]
            lines += [f"  {h}  {', '.join(a)}" for h, a in sorted(self.subdomains.items())]
        if self.related_map:
            lines += ["", "Nameserver / mail hosts:"]
            lines += [f"  {h}  {', '.join(a)}" for h, a in sorted(self.related_map.items())]
        rel = self.related_ips()
        if rel:
            lines += ["", "Other related IPs: " + ", ".join(rel)]
        if self.notes:
            lines += [""] + [f"Note: {n}" for n in sorted(self.notes)]
        return "\n".join(lines)
