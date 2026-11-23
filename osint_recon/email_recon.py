"""Email reconnaissance — validation, breach checking, and associated account discovery."""

from __future__ import annotations

import re
import hashlib
import socket
from dataclasses import dataclass, field
from typing import Optional

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class EmailReconResult:
    """Aggregated email recon findings."""

    email: str
    is_valid_format: bool = False
    mx_records: list[str] = field(default_factory=list)
    mx_valid: bool = False
    domain: str = ""
    breaches: list[dict] = field(default_factory=list)
    breach_check_error: str | None = None
    gravatar_url: str | None = None
    gravatar_exists: bool = False
    disposable: bool = False
    provider_info: str = ""


# Common disposable email domains
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "tempmail.com", "throwaway.email",
    "10minutemail.com", "trashmail.com", "yopmail.com", "maildrop.cc",
    "dispostable.com", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "guerrillamail.info", "guerrillamail.net", "guerrillamail.org",
    "tempail.com", "tempr.email", "discard.email", "mailnesia.com",
    "tmpmail.net", "tmpmail.org", "bupmail.com", "emailondeck.com",
    "fakeinbox.com", "mailcatch.com", "mailsac.com", "meltmail.com",
    "nada.email", "spamgourmet.com", "mytemp.email",
}

# Known email provider info
PROVIDER_MAP = {
    "gmail.com": "Google Gmail",
    "googlemail.com": "Google Gmail",
    "yahoo.com": "Yahoo Mail",
    "outlook.com": "Microsoft Outlook",
    "hotmail.com": "Microsoft Hotmail",
    "live.com": "Microsoft Live",
    "aol.com": "AOL Mail",
    "icloud.com": "Apple iCloud",
    "me.com": "Apple iCloud",
    "mac.com": "Apple iCloud",
    "protonmail.com": "ProtonMail (Encrypted)",
    "proton.me": "ProtonMail (Encrypted)",
    "tutanota.com": "Tutanota (Encrypted)",
    "zoho.com": "Zoho Mail",
    "yandex.com": "Yandex Mail",
    "mail.ru": "Mail.ru",
    "fastmail.com": "Fastmail",
}


def validate_email_format(email: str) -> bool:
    """Check if the email has a valid format."""
    pattern = r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_mx_records(domain: str) -> list[str]:
    """Look up MX records for the domain."""
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX")
        return sorted(
            [str(r.exchange).rstrip(".") for r in answers],
            key=lambda x: x,
        )
    except Exception:
        return []


def check_gravatar(email: str) -> tuple[bool, str]:
    """Check if a Gravatar exists for this email."""
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    try:
        resp = requests.head(url, timeout=5)
        exists = resp.status_code == 200
        profile_url = f"https://en.gravatar.com/{email_hash}"
        return exists, profile_url if exists else url
    except Exception:
        return False, ""


def check_hibp_breaches(email: str, api_key: str | None = None) -> tuple[list[dict], str | None]:
    """
    Check Have I Been Pwned for breaches.
    
    NOTE: The HIBP API v3 requires a paid API key for breach lookups.
    Without a key, this falls back to the hash-based password check
    or returns a helpful message.
    """
    breaches = []
    error = None

    if api_key:
        try:
            headers = {
                "hibp-api-key": api_key,
                "user-agent": "OSINT-Recon-Tool",
            }
            resp = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=10,
            )
            if resp.status_code == 200:
                breaches = resp.json()
            elif resp.status_code == 404:
                pass  # No breaches found
            elif resp.status_code == 401:
                error = "Invalid HIBP API key"
            elif resp.status_code == 429:
                error = "Rate limited — try again later"
            else:
                error = f"HIBP returned status {resp.status_code}"
        except Exception as exc:
            error = f"HIBP request failed: {exc}"
    else:
        error = (
            "No HIBP API key provided. Set HIBP_API_KEY env variable or use --hibp-key. "
            "Get a key at https://haveibeenpwned.com/API/Key"
        )

    return breaches, error


def recon_email(email: str, hibp_api_key: str | None = None) -> EmailReconResult:
    """Run full email reconnaissance."""
    result = EmailReconResult(email=email)

    # 1. Format validation
    result.is_valid_format = validate_email_format(email)
    if not result.is_valid_format:
        return result

    # 2. Extract domain
    result.domain = email.split("@")[1].lower()

    # 3. Provider identification
    result.provider_info = PROVIDER_MAP.get(result.domain, "Custom / Unknown Provider")

    # 4. Disposable check
    result.disposable = result.domain in DISPOSABLE_DOMAINS

    # 5. MX records
    result.mx_records = get_mx_records(result.domain)
    result.mx_valid = len(result.mx_records) > 0

    # 6. Gravatar
    result.gravatar_exists, result.gravatar_url = check_gravatar(email)

    # 7. HIBP breach check
    result.breaches, result.breach_check_error = check_hibp_breaches(email, hibp_api_key)

    return result


def print_email_results(result: EmailReconResult) -> None:
    """Pretty-print email recon results."""
    console.print()
    console.print(
        f"[bold cyan]📧 Email Recon Results for [yellow]{result.email}[/yellow][/bold cyan]"
    )
    console.print()

    # Basic Info
    info_table = Table(title="📋 Basic Analysis", border_style="blue", show_lines=True)
    info_table.add_column("Property", style="bold")
    info_table.add_column("Value")

    info_table.add_row(
        "Format Valid",
        "[green]✓ Yes[/green]" if result.is_valid_format else "[red]✗ No[/red]",
    )
    info_table.add_row("Domain", result.domain)
    info_table.add_row("Provider", result.provider_info)
    info_table.add_row(
        "Disposable Email",
        "[red]⚠ Yes — likely temporary[/red]" if result.disposable else "[green]No[/green]",
    )
    info_table.add_row(
        "MX Records Valid",
        "[green]✓ Yes[/green]" if result.mx_valid else "[red]✗ No MX records[/red]",
    )
    if result.mx_records:
        info_table.add_row("MX Servers", "\n".join(result.mx_records))
    info_table.add_row(
        "Gravatar",
        f"[green]✓ Found[/green] — {result.gravatar_url}" if result.gravatar_exists
        else "[dim]Not found[/dim]",
    )
    console.print(info_table)

    # Breach Results
    console.print()
    if result.breaches:
        breach_table = Table(
            title=f"🔓 Breaches Found ({len(result.breaches)})",
            border_style="red",
            show_lines=True,
        )
        breach_table.add_column("Name", style="bold red")
        breach_table.add_column("Date", style="yellow")
        breach_table.add_column("Records", justify="right")
        breach_table.add_column("Data Types", style="dim")
        for b in result.breaches:
            breach_table.add_row(
                b.get("Name", "Unknown"),
                b.get("BreachDate", "Unknown"),
                f"{b.get('PwnCount', 0):,}",
                ", ".join(b.get("DataClasses", [])[:5]),
            )
        console.print(breach_table)
    elif result.breach_check_error:
        console.print(f"[yellow]⚠ Breach check: {result.breach_check_error}[/yellow]")
    else:
        console.print("[green]✓ No known breaches found.[/green]")


def results_to_dict(result: EmailReconResult) -> dict:
    """Convert to serializable dict."""
    return {
        "module": "email_recon",
        "target": result.email,
        "valid_format": result.is_valid_format,
        "domain": result.domain,
        "provider": result.provider_info,
        "disposable": result.disposable,
        "mx_valid": result.mx_valid,
        "mx_records": result.mx_records,
        "gravatar_exists": result.gravatar_exists,
        "gravatar_url": result.gravatar_url,
        "breach_count": len(result.breaches),
        "breaches": result.breaches,
    }
