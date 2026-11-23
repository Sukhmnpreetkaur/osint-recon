"""IP geolocation module."""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class GeoResult:
    """IP geolocation result."""

    target: str
    resolved_ip: str = ""
    country: str = ""
    country_code: str = ""
    region: str = ""
    city: str = ""
    zip_code: str = ""
    latitude: float | None = None
    longitude: float | None = None
    timezone: str = ""
    isp: str = ""
    org: str = ""
    as_number: str = ""
    reverse_dns: str = ""
    map_url: str = ""
    error: str | None = None


def _resolve_to_ip(target: str) -> str:
    """Resolve a hostname to an IP if needed."""
    try:
        socket.inet_aton(target)
        return target
    except socket.error:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, target)
        return target
    except (socket.error, OSError):
        pass
    # It's a hostname — resolve it
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return ""


def geolocate(target: str) -> GeoResult:
    """Geolocate an IP or domain."""
    result = GeoResult(target=target)

    # Resolve
    ip = _resolve_to_ip(target)
    if not ip:
        result.error = f"Could not resolve '{target}' to an IP address."
        return result

    result.resolved_ip = ip

    # ip-api.com (free, no key required, 45 req/min)
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": (
                    "status,message,country,countryCode,region,regionName,"
                    "city,zip,lat,lon,timezone,isp,org,as,reverse,query"
                )
            },
            timeout=8,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result.country = data.get("country", "")
                result.country_code = data.get("countryCode", "")
                result.region = data.get("regionName", "")
                result.city = data.get("city", "")
                result.zip_code = data.get("zip", "")
                result.latitude = data.get("lat")
                result.longitude = data.get("lon")
                result.timezone = data.get("timezone", "")
                result.isp = data.get("isp", "")
                result.org = data.get("org", "")
                result.as_number = data.get("as", "")
                result.reverse_dns = data.get("reverse", "")

                if result.latitude and result.longitude:
                    result.map_url = (
                        f"https://www.google.com/maps?q={result.latitude},{result.longitude}"
                    )
            else:
                result.error = data.get("message", "Lookup failed")
        else:
            result.error = f"API returned status {resp.status_code}"
    except Exception as exc:
        result.error = str(exc)

    return result


def print_geo_results(result: GeoResult) -> None:
    """Pretty-print geolocation results."""
    console.print()
    console.print(
        f"[bold cyan]📍 Geolocation for [yellow]{result.target}[/yellow][/bold cyan]"
    )
    console.print()

    if result.error:
        console.print(f"[red]✗ {result.error}[/red]")
        return

    table = Table(border_style="magenta", show_lines=True)
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("IP Address", result.resolved_ip)
    if result.target != result.resolved_ip:
        table.add_row("Hostname", result.target)
    if result.reverse_dns:
        table.add_row("Reverse DNS", result.reverse_dns)
    table.add_row("Country", f"{result.country} ({result.country_code})")
    table.add_row("Region", result.region)
    table.add_row("City", result.city)
    table.add_row("ZIP / Postal", result.zip_code)
    table.add_row("Latitude", str(result.latitude) if result.latitude else "N/A")
    table.add_row("Longitude", str(result.longitude) if result.longitude else "N/A")
    table.add_row("Timezone", result.timezone)
    table.add_row("ISP", result.isp)
    table.add_row("Organization", result.org)
    table.add_row("AS Number", result.as_number)

    console.print(table)

    if result.map_url:
        console.print()
        console.print(
            Panel(
                f"[bold blue]{result.map_url}[/bold blue]",
                title="🗺  View on Map",
                border_style="green",
            )
        )


def results_to_dict(result: GeoResult) -> dict:
    """Convert to serializable dict."""
    return {
        "module": "geolocation",
        "target": result.target,
        "ip": result.resolved_ip,
        "country": result.country,
        "country_code": result.country_code,
        "region": result.region,
        "city": result.city,
        "zip": result.zip_code,
        "latitude": result.latitude,
        "longitude": result.longitude,
        "timezone": result.timezone,
        "isp": result.isp,
        "org": result.org,
        "as": result.as_number,
        "reverse_dns": result.reverse_dns,
        "map_url": result.map_url,
    }
