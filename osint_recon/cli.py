"""OSINT Recon — Main CLI entry point."""

from __future__ import annotations

import asyncio
import os
import sys
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

BANNER = r"""
   ____  _____ ___ _   _ _____   ____  _____ ____ ___  _   _ 
  / _ \/ ___|_ _| \ | |_   _| |  _ \| ____/ ___/ _ \| \ | |
 | | | \___ \| ||  \| | | |   | |_) |  _|| |  | | | |  \| |
 | |_| |___) | || |\  | | |   |  _ <| |__| |__| |_| | |\  |
  \___/|____/___|_| \_| |_|   |_| \_\_____\____\___/|_| \_|
                                                      v1.0.0
"""


def _show_banner() -> None:
    console.print(Panel(
        Text(BANNER, style="bold cyan"),
        subtitle="[dim]OSINT & Digital Footprinting Toolkit[/dim]",
        border_style="blue",
    ))


@click.group()
@click.version_option(version="1.0.0", prog_name="osint-recon")
def cli() -> None:
    """🔍 OSINT Recon — Open Source Intelligence & Digital Footprinting CLI Tool.

    A comprehensive toolkit for username searches, email reconnaissance,
    domain/IP analysis, phone lookups, metadata extraction, web scraping,
    Google dorking, and geolocation.
    """
    pass


# ── Username Search ──────────────────────────────────────────────────────────


@cli.command()
@click.argument("username")
@click.option("--json-out", "-j", type=click.Path(), help="Save results to JSON file.")
@click.option("--concurrency", "-c", default=20, help="Max concurrent requests.")
def username(username: str, json_out: str | None, concurrency: int) -> None:
    """🔍 Search for a USERNAME across 50+ social platforms."""
    _show_banner()
    from osint_recon.username_search import search_username, print_username_results, results_to_dict

    console.print(f"[bold]Searching for username [cyan]{username}[/cyan] across {50}+ platforms...[/bold]\n")

    with console.status("[bold green]Scanning platforms...", spinner="dots"):
        results = asyncio.run(search_username(username, max_concurrent=concurrency))

    print_username_results(username, results)

    if json_out:
        import json
        data = results_to_dict(username, results)
        with open(json_out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {json_out}[/green]")


# ── Email Recon ──────────────────────────────────────────────────────────────


@cli.command()
@click.argument("email")
@click.option("--hibp-key", envvar="HIBP_API_KEY", help="Have I Been Pwned API key.")
@click.option("--json-out", "-j", type=click.Path(), help="Save results to JSON file.")
def email(email: str, hibp_key: str | None, json_out: str | None) -> None:
    """📧 Perform reconnaissance on an EMAIL address."""
    _show_banner()
    from osint_recon.email_recon import recon_email, print_email_results, results_to_dict

    console.print(f"[bold]Analyzing email [cyan]{email}[/cyan]...[/bold]\n")

    with console.status("[bold green]Running email recon...", spinner="dots"):
        result = recon_email(email, hibp_api_key=hibp_key)

    print_email_results(result)

    if json_out:
        import json
        data = results_to_dict(result)
        with open(json_out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {json_out}[/green]")


# ── Domain / IP Recon ────────────────────────────────────────────────────────


@cli.command()
@click.argument("target")
@click.option("--skip-subdomains", is_flag=True, help="Skip subdomain enumeration (faster).")
@click.option("--json-out", "-j", type=click.Path(), help="Save results to JSON file.")
def domain(target: str, skip_subdomains: bool, json_out: str | None) -> None:
    """🌐 Perform domain/IP reconnaissance on TARGET."""
    _show_banner()
    from osint_recon.domain_recon import recon_domain, print_domain_results, results_to_dict

    console.print(f"[bold]Running domain recon on [cyan]{target}[/cyan]...[/bold]\n")

    with console.status("[bold green]Gathering intelligence...", spinner="dots"):
        result = recon_domain(target, skip_subdomains=skip_subdomains)

    print_domain_results(result)

    if json_out:
        import json
        data = results_to_dict(result)
        with open(json_out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {json_out}[/green]")


# ── Phone Lookup ─────────────────────────────────────────────────────────────


@cli.command()
@click.argument("number")
@click.option("--region", "-r", default="US", help="Default region code (e.g., US, IN, GB).")
@click.option("--numverify-key", envvar="NUMVERIFY_API_KEY", help="Numverify API key for real-time validation.")
@click.option("--twilio-sid", envvar="TWILIO_ACCOUNT_SID", help="Twilio Account SID for CNAM / Caller Name lookup.")
@click.option("--twilio-token", envvar="TWILIO_AUTH_TOKEN", help="Twilio Auth Token.")
@click.option("--no-live-search", is_flag=True, help="Disable real-time web footprinting.")
@click.option("--json-out", "-j", type=click.Path(), help="Save results to JSON file.")
def phone(
    number: str,
    region: str,
    numverify_key: str | None,
    twilio_sid: str | None,
    twilio_token: str | None,
    no_live_search: bool,
    json_out: str | None,
) -> None:
    """📱 Analyze a phone NUMBER — real-time carrier, CNAM/owner info, reverse directories."""
    _show_banner()
    from osint_recon.phone_lookup import analyze_phone, print_phone_results, results_to_dict

    console.print(f"[bold]Analyzing phone number [cyan]{number}[/cyan]...[/bold]\n")

    with console.status("[bold green]Conducting real-time phone intelligence...", spinner="dots"):
        result = analyze_phone(
            number,
            default_region=region,
            numverify_key=numverify_key,
            twilio_sid=twilio_sid,
            twilio_token=twilio_token,
            live_search=not no_live_search,
        )
    print_phone_results(result)

    if json_out:
        import json
        data = results_to_dict(result)
        with open(json_out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {json_out}[/green]")


# ── Metadata Extraction ─────────────────────────────────────────────────────


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--json-out", "-j", type=click.Path(), help="Save results to JSON file.")
def metadata(filepath: str, json_out: str | None) -> None:
    """📄 Extract metadata from a file (images, PDFs, documents)."""
    _show_banner()
    from osint_recon.metadata_extract import extract_metadata, print_metadata_results, results_to_dict

    console.print(f"[bold]Extracting metadata from [cyan]{filepath}[/cyan]...[/bold]\n")

    result = extract_metadata(filepath)
    print_metadata_results(result)

    if json_out:
        import json
        data = results_to_dict(result)
        with open(json_out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {json_out}[/green]")


# ── Google Dorks ─────────────────────────────────────────────────────────────


@cli.command()
@click.argument("target")
@click.option("--json-out", "-j", type=click.Path(), help="Save results to JSON file.")
def dorks(target: str, json_out: str | None) -> None:
    """🔎 Generate Google dork queries for a TARGET domain/keyword."""
    _show_banner()
    from osint_recon.web_scraper import build_dorks, print_dork_results, dorks_to_dict

    console.print(f"[bold]Generating dork queries for [cyan]{target}[/cyan]...[/bold]\n")

    dork_list = build_dorks(target)
    print_dork_results(target, dork_list)

    if json_out:
        import json
        data = dorks_to_dict(target, dork_list)
        with open(json_out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {json_out}[/green]")


# ── Web Scrape ───────────────────────────────────────────────────────────────


@cli.command()
@click.argument("url")
@click.option("--json-out", "-j", type=click.Path(), help="Save results to JSON file.")
def scrape(url: str, json_out: str | None) -> None:
    """🕸 Scrape a URL for emails, social links, tech stack, and more."""
    _show_banner()
    from osint_recon.web_scraper import scrape_url, print_scrape_results, scrape_to_dict

    console.print(f"[bold]Scraping [cyan]{url}[/cyan]...[/bold]\n")

    with console.status("[bold green]Fetching and parsing...", spinner="dots"):
        result = scrape_url(url)

    print_scrape_results(result)

    if json_out:
        import json
        data = scrape_to_dict(result)
        with open(json_out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {json_out}[/green]")


# ── Geolocation ──────────────────────────────────────────────────────────────


@cli.command()
@click.argument("target")
@click.option("--json-out", "-j", type=click.Path(), help="Save results to JSON file.")
def geolocate(target: str, json_out: str | None) -> None:
    """📍 Geolocate an IP address or domain."""
    _show_banner()
    from osint_recon.geolocation import geolocate as geo_lookup, print_geo_results, results_to_dict

    console.print(f"[bold]Geolocating [cyan]{target}[/cyan]...[/bold]\n")

    with console.status("[bold green]Looking up location...", spinner="dots"):
        result = geo_lookup(target)

    print_geo_results(result)

    if json_out:
        import json
        data = results_to_dict(result)
        with open(json_out, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"\n[green]✓ Results saved to {json_out}[/green]")


# ── Full Recon (all modules) ─────────────────────────────────────────────────


@cli.command()
@click.option("--username", "-u", help="Username to search.")
@click.option("--email", "-e", help="Email to investigate.")
@click.option("--domain", "-d", help="Domain or IP to recon.")
@click.option("--phone", "-p", help="Phone number to analyze.")
@click.option("--file", "-f", "filepath", type=click.Path(exists=True), help="File to extract metadata from.")
@click.option("--hibp-key", envvar="HIBP_API_KEY", help="Have I Been Pwned API key.")
@click.option("--numverify-key", envvar="NUMVERIFY_API_KEY", help="Numverify API key for real-time validation.")
@click.option("--twilio-sid", envvar="TWILIO_ACCOUNT_SID", help="Twilio Account SID for CNAM / Caller Name lookup.")
@click.option("--twilio-token", envvar="TWILIO_AUTH_TOKEN", help="Twilio Auth Token.")
@click.option("--output-dir", "-o", default=".", help="Output directory for reports.")
@click.option("--format", "formats", multiple=True, default=["json", "html"],
              type=click.Choice(["json", "html"]), help="Report formats.")
def fullrecon(
    username: str | None,
    email: str | None,
    domain: str | None,
    phone: str | None,
    filepath: str | None,
    hibp_key: str | None,
    numverify_key: str | None,
    twilio_sid: str | None,
    twilio_token: str | None,
    output_dir: str,
    formats: tuple[str, ...],
) -> None:
    """🚀 Run a full recon combining all modules. Provide one or more targets.

    Example:\n
      osint fullrecon -u johndoe -e john@example.com -d example.com
    """
    _show_banner()

    if not any([username, email, domain, phone, filepath]):
        console.print("[red]✗ Provide at least one target (--username, --email, --domain, --phone, or --file).[/red]")
        raise SystemExit(1)

    findings: list[dict] = []
    primary_target = username or email or domain or phone or filepath or "unknown"

    # Username
    if username:
        from osint_recon.username_search import search_username, print_username_results, results_to_dict
        console.print(f"\n[bold cyan]━━━ Username Search: {username} ━━━[/bold cyan]")
        with console.status("[bold green]Scanning platforms...", spinner="dots"):
            results = asyncio.run(search_username(username))
        print_username_results(username, results)
        findings.append(results_to_dict(username, results))

    # Email
    if email:
        from osint_recon.email_recon import recon_email, print_email_results
        from osint_recon.email_recon import results_to_dict as email_to_dict
        console.print(f"\n[bold cyan]━━━ Email Recon: {email} ━━━[/bold cyan]")
        with console.status("[bold green]Analyzing email...", spinner="dots"):
            result = recon_email(email, hibp_api_key=hibp_key)
        print_email_results(result)
        findings.append(email_to_dict(result))

    # Domain
    if domain:
        from osint_recon.domain_recon import recon_domain, print_domain_results
        from osint_recon.domain_recon import results_to_dict as domain_to_dict
        console.print(f"\n[bold cyan]━━━ Domain Recon: {domain} ━━━[/bold cyan]")
        with console.status("[bold green]Gathering domain intel...", spinner="dots"):
            result = recon_domain(domain)
        print_domain_results(result)
        findings.append(domain_to_dict(result))

    # Phone
    if phone:
        from osint_recon.phone_lookup import analyze_phone, print_phone_results
        from osint_recon.phone_lookup import results_to_dict as phone_to_dict
        console.print(f"\n[bold cyan]━━━ Phone Lookup: {phone} ━━━[/bold cyan]")
        with console.status("[bold green]Conducting real-time phone intelligence...", spinner="dots"):
            result = analyze_phone(
                phone,
                numverify_key=numverify_key,
                twilio_sid=twilio_sid,
                twilio_token=twilio_token,
            )
        print_phone_results(result)
        findings.append(phone_to_dict(result))

    # Metadata
    if filepath:
        from osint_recon.metadata_extract import extract_metadata, print_metadata_results
        from osint_recon.metadata_extract import results_to_dict as meta_to_dict
        console.print(f"\n[bold cyan]━━━ Metadata Extraction: {filepath} ━━━[/bold cyan]")
        result = extract_metadata(filepath)
        print_metadata_results(result)
        findings.append(meta_to_dict(result))

    # Generate reports
    if findings:
        from osint_recon.report import save_report
        console.print(f"\n[bold cyan]━━━ Generating Reports ━━━[/bold cyan]")
        saved = save_report(findings, primary_target, output_dir, list(formats))
        console.print(f"\n[bold green]✓ Full recon complete! {len(saved)} report(s) generated.[/bold green]")


if __name__ == "__main__":
    cli()
