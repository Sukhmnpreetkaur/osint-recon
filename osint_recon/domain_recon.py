"""Domain & IP reconnaissance — WHOIS, DNS, subdomains, reverse IP, headers."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Optional, Any

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

console = Console()


@dataclass
class DomainReconResult:
    """Aggregated domain/IP recon findings."""

    target: str
    is_ip: bool = False

    # WHOIS
    whois_data: dict[str, Any] = field(default_factory=dict)
    whois_error: str | None = None

    # DNS
    dns_records: dict[str, list[str]] = field(default_factory=dict)

    # IP resolution
    resolved_ips: list[str] = field(default_factory=list)

    # Geolocation (IP-based)
    geo_data: dict[str, Any] = field(default_factory=dict)

    # HTTP headers
    http_headers: dict[str, str] = field(default_factory=dict)
    server_tech: list[str] = field(default_factory=list)

    # Subdomains
    subdomains: list[str] = field(default_factory=list)

    # Reverse DNS
    reverse_dns: str | None = None

    # SSL/TLS Info
    ssl_info: dict[str, Any] = field(default_factory=dict)


def _is_ip_address(target: str) -> bool:
    """Check if the target is an IP address."""
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return True
    except (socket.error, OSError):
        return False


def whois_lookup(domain: str) -> tuple[dict[str, Any], str | None]:
    """Perform WHOIS lookup."""
    try:
        import whois
        w = whois.whois(domain)
        data = {}
        for key in [
            "domain_name", "registrar", "whois_server", "creation_date",
            "expiration_date", "updated_date", "name_servers", "status",
            "emails", "org", "country", "state", "city", "address",
            "registrant", "dnssec",
        ]:
            val = getattr(w, key, None)
            if val is not None:
                if isinstance(val, list):
                    data[key] = [str(v) for v in val]
                else:
                    data[key] = str(val)
        return data, None
    except Exception as exc:
        return {}, str(exc)[:200]


def dns_lookup(domain: str) -> dict[str, list[str]]:
    """Resolve common DNS record types."""
    import dns.resolver

    records: dict[str, list[str]] = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass

    return records


def resolve_ip(domain: str) -> list[str]:
    """Resolve domain to IP addresses."""
    try:
        results = socket.getaddrinfo(domain, None)
        ips = list({r[4][0] for r in results})
        return sorted(ips)
    except socket.gaierror:
        return []


def reverse_dns_lookup(ip: str) -> str | None:
    """Perform reverse DNS lookup on an IP."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def geolocate_ip(ip: str) -> dict[str, Any]:
    """Get geolocation data for an IP using ip-api.com (free, no key)."""
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return {}


def grab_http_headers(domain: str) -> tuple[dict[str, str], list[str]]:
    """Grab HTTP response headers and detect server technologies."""
    headers: dict[str, str] = {}
    tech: list[str] = []

    for scheme in ["https", "http"]:
        try:
            resp = requests.head(
                f"{scheme}://{domain}",
                timeout=8,
                allow_redirects=True,
                headers={"User-Agent": "OSINT-Recon/1.0"},
            )
            headers = dict(resp.headers)

            # Detect technologies from headers
            server = headers.get("Server", "")
            if server:
                tech.append(f"Server: {server}")
            powered = headers.get("X-Powered-By", "")
            if powered:
                tech.append(f"Powered By: {powered}")
            if "X-AspNet-Version" in headers:
                tech.append(f"ASP.NET: {headers['X-AspNet-Version']}")
            if "X-Drupal-Cache" in headers:
                tech.append("CMS: Drupal")
            if "X-Generator" in headers:
                tech.append(f"Generator: {headers['X-Generator']}")
            if "X-WordPress" in headers or "wp-" in str(headers):
                tech.append("CMS: WordPress")

            # Security headers check
            security_headers = [
                "Strict-Transport-Security",
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "X-XSS-Protection",
                "Referrer-Policy",
                "Permissions-Policy",
            ]
            for sh in security_headers:
                if sh in headers:
                    tech.append(f"🛡 {sh}: present")
                else:
                    tech.append(f"⚠ {sh}: MISSING")

            break  # Success, no need to try HTTP if HTTPS worked
        except Exception:
            continue

    return headers, tech


def enumerate_subdomains(domain: str) -> list[str]:
    """Enumerate subdomains using common wordlist + DNS brute-force."""
    common_subs = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "ns3", "ns4", "dns", "dns1", "dns2", "api", "dev", "staging", "test",
        "app", "blog", "shop", "store", "admin", "portal", "vpn", "remote",
        "secure", "login", "m", "mobile", "cdn", "media", "static", "assets",
        "img", "images", "video", "docs", "wiki", "help", "support", "status",
        "monitor", "git", "svn", "repo", "ci", "jenkins", "jira", "confluence",
        "grafana", "kibana", "elastic", "prometheus", "sentry", "mysql", "db",
        "database", "redis", "mongo", "postgres", "mq", "rabbitmq", "kafka",
        "cloud", "aws", "s3", "gcp", "azure", "kubernetes", "k8s", "docker",
        "registry", "sandbox", "demo", "preview", "beta", "alpha", "staging2",
        "internal", "intranet", "extranet", "gateway", "proxy", "lb", "edge",
        "node1", "node2", "backup", "archive", "old", "new", "v2", "v3",
    ]

    found: list[str] = []

    for sub in common_subs:
        subdomain = f"{sub}.{domain}"
        try:
            socket.getaddrinfo(subdomain, None)
            found.append(subdomain)
        except socket.gaierror:
            pass

    return sorted(found)


def recon_domain(target: str, skip_subdomains: bool = False) -> DomainReconResult:
    """Run full domain/IP reconnaissance."""
    result = DomainReconResult(target=target)
    result.is_ip = _is_ip_address(target)

    if result.is_ip:
        # IP-based recon
        result.resolved_ips = [target]
        result.reverse_dns = reverse_dns_lookup(target)
        result.geo_data = geolocate_ip(target)
    else:
        # Domain-based recon
        # WHOIS
        result.whois_data, result.whois_error = whois_lookup(target)

        # DNS
        result.dns_records = dns_lookup(target)

        # IP resolution
        result.resolved_ips = resolve_ip(target)

        # Geolocation on first IP
        if result.resolved_ips:
            result.geo_data = geolocate_ip(result.resolved_ips[0])

        # HTTP headers
        result.http_headers, result.server_tech = grab_http_headers(target)

        # Subdomains
        if not skip_subdomains:
            result.subdomains = enumerate_subdomains(target)

    return result


def print_domain_results(result: DomainReconResult) -> None:
    """Pretty-print domain/IP recon results."""
    console.print()
    label = "IP" if result.is_ip else "Domain"
    console.print(
        f"[bold cyan]🌐 {label} Recon Results for [yellow]{result.target}[/yellow][/bold cyan]"
    )
    console.print()

    # WHOIS
    if result.whois_data:
        whois_table = Table(title="📝 WHOIS Data", border_style="blue", show_lines=True)
        whois_table.add_column("Field", style="bold")
        whois_table.add_column("Value")
        for k, v in result.whois_data.items():
            if isinstance(v, list):
                whois_table.add_row(k, "\n".join(v[:10]))
            else:
                whois_table.add_row(k, str(v))
        console.print(whois_table)
        console.print()
    elif result.whois_error:
        console.print(f"[yellow]⚠ WHOIS: {result.whois_error}[/yellow]")

    # Resolved IPs
    if result.resolved_ips:
        console.print(
            Panel(
                "\n".join(result.resolved_ips),
                title="🖥 Resolved IPs",
                border_style="green",
            )
        )

    # Reverse DNS
    if result.reverse_dns:
        console.print(f"[cyan]🔄 Reverse DNS:[/cyan] {result.reverse_dns}")

    # DNS Records
    if result.dns_records:
        dns_table = Table(title="📡 DNS Records", border_style="cyan", show_lines=True)
        dns_table.add_column("Type", style="bold")
        dns_table.add_column("Records")
        for rtype, records in sorted(result.dns_records.items()):
            dns_table.add_row(rtype, "\n".join(records))
        console.print(dns_table)
        console.print()

    # Geolocation
    if result.geo_data:
        geo_table = Table(title="📍 IP Geolocation", border_style="magenta", show_lines=True)
        geo_table.add_column("Property", style="bold")
        geo_table.add_column("Value")
        for key in ["query", "country", "regionName", "city", "zip", "lat", "lon", "timezone", "isp", "org", "as"]:
            val = result.geo_data.get(key)
            if val is not None:
                geo_table.add_row(key, str(val))
        console.print(geo_table)
        console.print()

    # Server Tech & Security
    if result.server_tech:
        tree = Tree("🔧 Server Technology & Security Headers")
        for item in result.server_tech:
            if item.startswith("🛡"):
                tree.add(f"[green]{item}[/green]")
            elif item.startswith("⚠"):
                tree.add(f"[yellow]{item}[/yellow]")
            else:
                tree.add(f"[cyan]{item}[/cyan]")
        console.print(tree)
        console.print()

    # Subdomains
    if result.subdomains:
        sub_table = Table(
            title=f"🌿 Subdomains Found ({len(result.subdomains)})",
            border_style="green",
        )
        sub_table.add_column("Subdomain", style="cyan")
        for s in result.subdomains:
            sub_table.add_row(s)
        console.print(sub_table)


def results_to_dict(result: DomainReconResult) -> dict:
    """Convert to serializable dict."""
    return {
        "module": "domain_recon",
        "target": result.target,
        "is_ip": result.is_ip,
        "whois": result.whois_data,
        "dns_records": result.dns_records,
        "resolved_ips": result.resolved_ips,
        "reverse_dns": result.reverse_dns,
        "geolocation": result.geo_data,
        "server_tech": result.server_tech,
        "subdomains": result.subdomains,
        "http_headers": {
            k: v for k, v in result.http_headers.items()
        } if result.http_headers else {},
    }
