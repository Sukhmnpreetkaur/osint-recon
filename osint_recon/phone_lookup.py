"""Phone number lookup — real-time validation, carrier, CNAM/owner lookup, web footprinting."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Any

import requests
import phonenumbers
from phonenumbers import (
    carrier,
    geocoder,
    timezone,
    PhoneNumberFormat,
    NumberParseException,
)
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class PhoneResult:
    """Phone number analysis result."""

    raw_input: str
    valid: bool = False
    possible: bool = False
    country_code: int | None = None
    national_number: str = ""
    international_format: str = ""
    national_format: str = ""
    e164_format: str = ""
    rfc3966_format: str = ""
    country: str = ""
    region: str = ""
    carrier_name: str = ""
    line_type: str = ""
    timezones: list[str] | None = None
    parse_error: str | None = None

    # Real-Time & Owner Data
    caller_name: str | None = None
    caller_type: str | None = None
    live_carrier: str | None = None
    live_valid: bool | None = None
    live_location: str | None = None
    api_error: str | None = None

    # Web footprinting & reverse lookup directories
    directory_links: dict[str, str] = field(default_factory=dict)
    dork_queries: list[dict[str, str]] = field(default_factory=list)
    web_mentions: list[dict[str, str]] = field(default_factory=list)


LINE_TYPE_MAP = {
    0: "Fixed Line",
    1: "Mobile",
    2: "Fixed Line or Mobile",
    3: "Toll Free",
    4: "Premium Rate",
    5: "Shared Cost",
    6: "VoIP",
    7: "Personal Number",
    8: "Pager",
    9: "UAN (Universal Access)",
    10: "Voicemail",
    27: "Emergency",
    28: "Short Code",
    29: "Standard Rate",
}


def _lookup_numverify(number_e164: str, api_key: str) -> dict[str, Any]:
    """Query Numverify API for real-time validation and carrier information."""
    try:
        clean_num = number_e164.lstrip("+")
        url = f"https://apilayer.net/api/validate?access_key={api_key}&number={clean_num}"
        resp = requests.get(url, timeout=10)
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        return {"error": str(exc)}
    return {}


def _lookup_twilio_cnam(number_e164: str, account_sid: str, auth_token: str) -> dict[str, Any]:
    """
    Query Twilio Lookup API v2 with CNAM/CallerName Add-on.
    Retrieves real-time registered subscriber / caller name (Caller ID).
    """
    try:
        url = f"https://lookups.twilio.com/v2/PhoneNumbers/{urllib.parse.quote(number_e164)}"
        params = {"Fields": "caller_name,line_type_intelligence"}
        resp = requests.get(url, params=params, auth=(account_sid, auth_token), timeout=10)
        if resp.status_code == 200:
            return resp.json()
        return {"error": f"Twilio API status {resp.status_code}: {resp.text}"}
    except Exception as exc:
        return {"error": str(exc)}


def _generate_directory_links(result: PhoneResult) -> dict[str, str]:
    """Generate direct links to leading reverse phone lookup directories."""
    clean_national = re.sub(r"\D", "", result.national_number)
    clean_e164 = result.e164_format.lstrip("+")

    links = {
        "Truecaller": f"https://www.truecaller.com/search/{result.country_code}/{clean_national}",
        "Sync.me": f"https://sync.me/search/?number=%2B{clean_e164}",
        "NumLookup": f"https://www.numlookup.com/",
        "Whitepages (US)": f"https://www.whitepages.com/phone/{clean_national}",
        "That's Them": f"https://thatsthem.com/phone/{result.national_format.replace(' ', '-')}",
        "SpyDialer": f"https://www.spydialer.com/",
    }
    return links


def _generate_phone_dorks(result: PhoneResult) -> list[dict[str, str]]:
    """Generate targeted search queries across public web and social platforms."""
    variants = [
        f'"{result.e164_format}"',
        f'"{result.national_format}"',
        f'"{result.international_format}"',
        f'"{result.national_number}"',
    ]
    query_variants = " OR ".join(variants[:3])

    templates = [
        ("General Mentions", f"Find all public web mentions of this number",
         f'{query_variants}'),
        ("Resumes & Resumes/CVs", f"Find resumes, CVs, or portfolios listing this number",
         f'({query_variants}) (resume OR CV OR "contact me" OR "email me")'),
        ("Social Profiles", f"Find profiles on LinkedIn, Twitter, Facebook, Instagram",
         f'({query_variants}) (site:linkedin.com OR site:twitter.com OR site:x.com OR site:facebook.com OR site:instagram.com)'),
        ("Classifieds & Directories", f"Find classifieds, seller ads, or business listings",
         f'({query_variants}) (site:craigslist.org OR site:gumtree.com OR site:olx.in OR site:yellowpages.com)'),
        ("Leaked Dumps & Pastes", f"Find occurrences in leaked dumps or pastebins",
         f'({query_variants}) (site:pastebin.com OR site:justpaste.it OR site:ghostbin.com)'),
        ("GitHub Code & Commits", f"Find accidental commits or developer profiles",
         f'site:github.com ({query_variants})'),
    ]

    dorks = []
    for name, desc, query in templates:
        google_url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        dorks.append({
            "name": name,
            "description": desc,
            "query": query,
            "url": google_url,
        })
    return dorks


def _search_live_web_mentions(query: str, max_results: int = 5) -> list[dict[str, str]]:
    """
    Search DuckDuckGo HTML for real-time public web mentions of the phone number.
    Returns titles, URLs, and snippets without requiring an API key.
    """
    results: list[dict[str, str]] = []
    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
        }
        url = "https://html.duckduckgo.com/html/"
        resp = requests.post(url, data={"q": query}, headers=headers, timeout=8)
        if resp.status_code == 200:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(resp.text, "html.parser")
            for result_elem in soup.find_all("div", class_="result", limit=max_results):
                title_elem = result_elem.find("a", class_="result__a")
                snippet_elem = result_elem.find("a", class_="result__snippet")
                if title_elem and snippet_elem:
                    raw_link = title_elem.get("href", "")
                    # Extract original link from duckduckgo redirect if present
                    parsed_link = raw_link
                    if "uddg=" in raw_link:
                        match = re.search(r"uddg=([^&]+)", raw_link)
                        if match:
                            parsed_link = urllib.parse.unquote(match.group(1))
                    results.append({
                        "title": title_elem.get_text(strip=True),
                        "snippet": snippet_elem.get_text(strip=True),
                        "url": parsed_link,
                    })
    except Exception:
        pass
    return results


def analyze_phone(
    number: str,
    default_region: str = "US",
    numverify_key: str | None = None,
    twilio_sid: str | None = None,
    twilio_token: str | None = None,
    live_search: bool = True,
) -> PhoneResult:
    """
    Analyze a phone number with telecom parsing, real-time API queries,
    and public web footprinting.
    """
    result = PhoneResult(raw_input=number)

    try:
        parsed = phonenumbers.parse(number, default_region)
    except NumberParseException as exc:
        result.parse_error = str(exc)
        return result

    result.valid = phonenumbers.is_valid_number(parsed)
    result.possible = phonenumbers.is_possible_number(parsed)
    result.country_code = parsed.country_code
    result.national_number = str(parsed.national_number)

    # Standard Formats
    result.international_format = phonenumbers.format_number(
        parsed, PhoneNumberFormat.INTERNATIONAL
    )
    result.national_format = phonenumbers.format_number(
        parsed, PhoneNumberFormat.NATIONAL
    )
    result.e164_format = phonenumbers.format_number(
        parsed, PhoneNumberFormat.E164
    )
    result.rfc3966_format = phonenumbers.format_number(
        parsed, PhoneNumberFormat.RFC3966
    )

    # Static Geolocation & Telecom
    result.country = geocoder.country_name_for_number(parsed, "en") or ""
    result.region = geocoder.description_for_number(parsed, "en") or ""
    result.carrier_name = carrier.name_for_number(parsed, "en") or ""

    number_type = phonenumbers.number_type(parsed)
    result.line_type = LINE_TYPE_MAP.get(number_type, f"Unknown ({number_type})")

    try:
        tzs = timezone.time_zones_for_number(parsed)
        result.timezones = list(tzs) if tzs else None
    except Exception:
        result.timezones = None

    # Real-Time Lookup 1: Twilio Lookup v2 (Caller ID / Owner Name via CNAM)
    if twilio_sid and twilio_token:
        tw_data = _lookup_twilio_cnam(result.e164_format, twilio_sid, twilio_token)
        if "error" not in tw_data:
            cname = tw_data.get("caller_name") or {}
            result.caller_name = cname.get("caller_name")
            result.caller_type = cname.get("caller_type")
            line_info = tw_data.get("line_type_intelligence") or {}
            if line_info.get("carrier_name"):
                result.live_carrier = line_info.get("carrier_name")
            if line_info.get("type"):
                result.line_type = line_info.get("type").capitalize()
        else:
            result.api_error = tw_data.get("error")

    # Real-Time Lookup 2: Numverify API (Live Validation & Carrier)
    if numverify_key and not result.caller_name:
        nv_data = _lookup_numverify(result.e164_format, numverify_key)
        if nv_data.get("valid") is not None:
            result.live_valid = nv_data.get("valid")
            if nv_data.get("carrier"):
                result.live_carrier = nv_data.get("carrier")
            if nv_data.get("location"):
                result.live_location = nv_data.get("location")
            if nv_data.get("line_type"):
                result.line_type = nv_data.get("line_type").capitalize()

    # Generate Reverse Lookup Directory Links
    result.directory_links = _generate_directory_links(result)

    # Generate Targeted Google Dorks
    result.dork_queries = _generate_phone_dorks(result)

    # Real-Time Web Search for Public Mentions / Owner Signatures
    if live_search and result.valid:
        search_query = f'"{result.e164_format}" OR "{result.national_format}"'
        result.web_mentions = _search_live_web_mentions(search_query, max_results=4)

    return result


def print_phone_results(result: PhoneResult) -> None:
    """Pretty-print phone analysis results with real-time intelligence."""
    console.print()
    console.print(
        f"[bold cyan]📱 Phone Number Analysis for [yellow]{result.raw_input}[/yellow][/bold cyan]"
    )
    console.print()

    if result.parse_error:
        console.print(f"[red]✗ Parse error: {result.parse_error}[/red]")
        return

    # Basic Info Table
    table = Table(title="📋 Telecom & Line Details", border_style="blue", show_lines=True)
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row(
        "Valid",
        "[green]✓ Yes[/green]" if result.valid else "[red]✗ No[/red]",
    )
    table.add_row(
        "Possible",
        "[green]✓ Yes[/green]" if result.possible else "[yellow]⚠ No[/yellow]",
    )
    table.add_row("Country Code", f"+{result.country_code}")
    table.add_row("National Number", result.national_number)
    table.add_row("International", result.international_format)
    table.add_row("National", result.national_format)
    table.add_row("E.164", result.e164_format)
    table.add_row("Country", result.country or "[dim]Unknown[/dim]")
    table.add_row("Region / City", result.region or "[dim]Unknown[/dim]")
    table.add_row("Carrier", result.live_carrier or result.carrier_name or "[dim]Unknown[/dim]")
    table.add_row("Line Type", result.line_type)
    if result.timezones:
        table.add_row("Timezones", "\n".join(result.timezones))

    console.print(table)

    # Caller ID / Owner Information Panel
    console.print()
    if result.caller_name:
        owner_content = (
            f"[bold green]Registered Name:[/bold green] {result.caller_name}\n"
            f"[bold]Caller Type:[/bold] {result.caller_type or 'Consumer / Personal'}"
        )
        console.print(Panel(owner_content, title="👤 Real-Time Caller ID / Owner Info", border_style="green"))
    else:
        owner_notice = (
            "[yellow]Note on Phone Owner Info:[/yellow]\n"
            "Carrier subscriber names (CNAM) are private telecom records. To query registered names in real-time:\n"
            " • Provide a Twilio Lookup CNAM key: [bold]--twilio-sid[/bold] and [bold]--twilio-token[/bold]\n"
            " • Or use the reverse directory search links and web footprinting below."
        )
        console.print(Panel(owner_notice, title="👤 Owner / Caller ID Status", border_style="yellow"))

    # Live Web Mentions
    if result.web_mentions:
        console.print()
        mentions_table = Table(
            title=f"🌐 Real-Time Web Mentions Found ({len(result.web_mentions)})",
            border_style="magenta",
            show_lines=True,
        )
        mentions_table.add_column("Source / Title", style="bold cyan", max_width=40)
        mentions_table.add_column("Snippet Preview", style="dim", max_width=60)
        mentions_table.add_column("URL", style="blue")
        for m in result.web_mentions:
            mentions_table.add_row(m.get("title", ""), m.get("snippet", ""), m.get("url", ""))
        console.print(mentions_table)

    # Reverse Lookup Directory Links
    if result.directory_links:
        console.print()
        dir_table = Table(
            title="🔍 Reverse Lookup Directories (One-Click Investigation)",
            border_style="green",
            show_lines=True,
        )
        dir_table.add_column("Service", style="bold green")
        dir_table.add_column("Direct Lookup URL", style="cyan")
        for name, link in result.directory_links.items():
            dir_table.add_row(name, link)
        console.print(dir_table)

    # Google Dorks for Deep Footprinting
    if result.dork_queries:
        console.print()
        dork_table = Table(
            title="🔎 Targeted Phone Search Dorks",
            border_style="cyan",
            show_lines=True,
        )
        dork_table.add_column("Target Category", style="bold")
        dork_table.add_column("Search Query", style="dim")
        dork_table.add_column("Google Search URL", style="blue", max_width=50)
        for d in result.dork_queries[:4]:
            dork_table.add_row(d["name"], d["query"], d["url"])
        console.print(dork_table)


def results_to_dict(result: PhoneResult) -> dict:
    """Convert to serializable dict."""
    return {
        "module": "phone_lookup",
        "target": result.raw_input,
        "valid": result.valid,
        "possible": result.possible,
        "country_code": result.country_code,
        "national_number": result.national_number,
        "international_format": result.international_format,
        "national_format": result.national_format,
        "e164_format": result.e164_format,
        "country": result.country,
        "region": result.region,
        "carrier": result.live_carrier or result.carrier_name,
        "line_type": result.line_type,
        "timezones": result.timezones,
        "caller_name": result.caller_name,
        "caller_type": result.caller_type,
        "directory_links": result.directory_links,
        "web_mentions": result.web_mentions,
        "dork_queries": result.dork_queries,
    }
