"""Web scraping utilities and Google dork query builder."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse, urljoin

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree

console = Console()

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}


# ── Google Dork Builder ──────────────────────────────────────────────────────


@dataclass
class DorkQuery:
    """A generated Google dork query."""

    name: str
    description: str
    query: str
    google_url: str


def build_dorks(target: str) -> list[DorkQuery]:
    """Build a comprehensive set of Google dork queries for a target domain/keyword."""

    dork_templates = [
        # Information Disclosure
        ("Directory Listing", "Find open directory listings",
         'site:{target} intitle:"index of"'),
        ("Exposed Files", "Find exposed documents",
         'site:{target} filetype:pdf OR filetype:doc OR filetype:xls OR filetype:csv'),
        ("Config Files", "Find exposed configuration files",
         'site:{target} filetype:env OR filetype:ini OR filetype:conf OR filetype:cfg'),
        ("Log Files", "Find exposed log files",
         'site:{target} filetype:log OR filetype:txt inurl:log'),
        ("SQL Files", "Find exposed database dumps",
         'site:{target} filetype:sql OR filetype:db OR filetype:sqlite'),
        ("Backup Files", "Find backup files",
         'site:{target} filetype:bak OR filetype:old OR filetype:backup'),

        # Credentials & Sensitive Data
        ("Passwords", "Find pages mentioning passwords",
         'site:{target} intext:"password" OR intext:"passwd" filetype:txt OR filetype:log'),
        ("API Keys", "Find exposed API keys",
         'site:{target} intext:"api_key" OR intext:"apikey" OR intext:"api-key"'),
        ("Emails", "Find email addresses on the site",
         'site:{target} intext:"@{target}"'),
        ("Private Keys", "Find exposed private keys",
         'site:{target} filetype:pem OR filetype:key OR filetype:ppk'),

        # Technology Discovery
        ("WordPress", "Detect WordPress installations",
         'site:{target} inurl:wp-content OR inurl:wp-admin'),
        ("Login Pages", "Find login/admin pages",
         'site:{target} inurl:login OR inurl:admin OR inurl:signin'),
        ("PHP Info", "Find PHP info pages",
         'site:{target} inurl:phpinfo OR intitle:"phpinfo()"'),
        ("Git Exposure", "Find exposed .git directories",
         'site:{target} inurl:".git"'),

        # Error Messages
        ("SQL Errors", "Find SQL error messages",
         'site:{target} intext:"sql syntax" OR intext:"mysql_fetch"'),
        ("PHP Errors", "Find PHP errors",
         'site:{target} intext:"Warning: " OR intext:"Fatal error"'),
        ("Stack Traces", "Find exposed stack traces",
         'site:{target} intext:"Exception" intext:"stack trace"'),

        # Subdomain & URL Discovery
        ("Subdomains", "Discover subdomains via Google",
         'site:*.{target} -www'),
        ("URL Parameters", "Find URLs with parameters",
         'site:{target} inurl:"?" inurl:"="'),

        # Social Media / Mentions
        ("LinkedIn Mentions", "Find LinkedIn mentions",
         'site:linkedin.com "{target}"'),
        ("GitHub Mentions", "Find GitHub mentions",
         'site:github.com "{target}"'),
        ("Pastebin Mentions", "Find pastebin leaks",
         'site:pastebin.com "{target}"'),
        ("Reddit Mentions", "Find Reddit discussions",
         'site:reddit.com "{target}"'),

        # Document Discovery
        ("Spreadsheets", "Find spreadsheets",
         'site:{target} filetype:xlsx OR filetype:csv'),
        ("Presentations", "Find presentations",
         'site:{target} filetype:pptx OR filetype:ppt'),
        ("XML/JSON Data", "Find exposed data files",
         'site:{target} filetype:xml OR filetype:json'),
    ]

    dorks: list[DorkQuery] = []
    for name, desc, query_tmpl in dork_templates:
        query = query_tmpl.replace("{target}", target)
        google_url = f"https://www.google.com/search?q={requests.utils.quote(query)}"
        dorks.append(DorkQuery(
            name=name,
            description=desc,
            query=query,
            google_url=google_url,
        ))

    return dorks


# ── Web Scraper ──────────────────────────────────────────────────────────────


@dataclass
class ScrapeResult:
    """Web scraping result."""

    url: str
    status_code: int | None = None
    title: str = ""
    description: str = ""
    links: list[dict[str, str]] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    social_links: list[dict[str, str]] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    headers_of_page: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)
    forms: list[dict[str, str]] = field(default_factory=list)
    error: str | None = None


SOCIAL_PATTERNS = {
    "Twitter/X": r"(?:https?://)?(?:www\.)?(?:twitter\.com|x\.com)/[\w]+",
    "Facebook": r"(?:https?://)?(?:www\.)?facebook\.com/[\w.]+",
    "Instagram": r"(?:https?://)?(?:www\.)?instagram\.com/[\w.]+",
    "LinkedIn": r"(?:https?://)?(?:www\.)?linkedin\.com/(?:in|company)/[\w\-]+",
    "YouTube": r"(?:https?://)?(?:www\.)?youtube\.com/(?:c/|channel/|@)[\w\-]+",
    "GitHub": r"(?:https?://)?(?:www\.)?github\.com/[\w\-]+",
    "TikTok": r"(?:https?://)?(?:www\.)?tiktok\.com/@[\w.]+",
    "Pinterest": r"(?:https?://)?(?:www\.)?pinterest\.com/[\w]+",
}


def scrape_url(url: str) -> ScrapeResult:
    """Scrape a URL and extract useful OSINT information."""
    result = ScrapeResult(url=url)

    # Normalize URL
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
        result.url = url

    try:
        resp = requests.get(url, headers=HEADERS, timeout=15, allow_redirects=True)
        result.status_code = resp.status_code
    except Exception as exc:
        result.error = str(exc)
        return result

    html = resp.text
    soup = BeautifulSoup(html, "html.parser")
    parsed_url = urlparse(url)
    base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"

    # Title
    title_tag = soup.find("title")
    result.title = title_tag.get_text(strip=True) if title_tag else ""

    # Meta description
    meta_desc = soup.find("meta", attrs={"name": "description"})
    if meta_desc:
        result.description = meta_desc.get("content", "")

    # Links
    seen_urls = set()
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        full_url = urljoin(url, href)
        text = a_tag.get_text(strip=True)[:100]
        if full_url not in seen_urls:
            seen_urls.add(full_url)
            result.links.append({"url": full_url, "text": text})

    # Emails
    email_pattern = r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    emails = set(re.findall(email_pattern, html))
    result.emails = sorted(emails)

    # Phone numbers (basic extraction)
    phone_pattern = r'[\+]?[(]?[0-9]{1,4}[)]?[\-\s\./0-9]{7,15}'
    phones = set(re.findall(phone_pattern, html))
    result.phone_numbers = sorted(p.strip() for p in phones if len(p.strip()) >= 10)

    # Social media links
    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = re.findall(pattern, html)
        for match in set(matches):
            result.social_links.append({"platform": platform, "url": match})

    # Technologies
    techs = []
    if soup.find(attrs={"data-reactroot": True}) or "react" in html.lower():
        techs.append("React")
    if "angular" in html.lower():
        techs.append("Angular")
    if "vue" in html.lower() or soup.find(attrs={"data-v-": True}):
        techs.append("Vue.js")
    if soup.find("script", src=re.compile(r"jquery", re.I)):
        techs.append("jQuery")
    if soup.find("link", href=re.compile(r"bootstrap", re.I)):
        techs.append("Bootstrap")
    if "wp-content" in html or "wordpress" in html.lower():
        techs.append("WordPress")
    if "shopify" in html.lower():
        techs.append("Shopify")
    if "wix" in html.lower():
        techs.append("Wix")
    if "squarespace" in html.lower():
        techs.append("Squarespace")
    if soup.find("meta", attrs={"name": "generator"}):
        gen = soup.find("meta", attrs={"name": "generator"})
        techs.append(f"Generator: {gen.get('content', '')}")
    result.technologies = techs

    # Page headings
    for level in range(1, 4):
        for h in soup.find_all(f"h{level}"):
            text = h.get_text(strip=True)[:150]
            if text:
                result.headers_of_page.append(f"H{level}: {text}")

    # Images
    for img in soup.find_all("img", src=True):
        img_url = urljoin(url, img["src"])
        result.images.append(img_url)

    # Scripts (external)
    for script in soup.find_all("script", src=True):
        script_url = urljoin(url, script["src"])
        result.scripts.append(script_url)

    # Forms
    for form in soup.find_all("form"):
        form_data = {
            "action": urljoin(url, form.get("action", "")),
            "method": form.get("method", "GET").upper(),
        }
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inputs.append(inp.get("name", inp.get("id", "unnamed")))
        form_data["fields"] = ", ".join(inputs[:20])
        result.forms.append(form_data)

    return result


def print_dork_results(target: str, dorks: list[DorkQuery]) -> None:
    """Pretty-print Google dork queries."""
    console.print()
    console.print(
        f"[bold cyan]🔎 Google Dork Queries for [yellow]{target}[/yellow][/bold cyan]"
    )
    console.print("[dim]Open these links in your browser to run the searches.[/dim]")
    console.print()

    table = Table(border_style="blue", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Query", style="cyan")
    table.add_column("URL", style="dim", max_width=60)

    for dork in dorks:
        table.add_row(dork.name, dork.query, dork.google_url)

    console.print(table)
    console.print(f"\n[dim]Total: {len(dorks)} dork queries generated[/dim]")


def print_scrape_results(result: ScrapeResult) -> None:
    """Pretty-print scrape results."""
    console.print()
    console.print(
        f"[bold cyan]🕸 Web Scrape Results for [yellow]{result.url}[/yellow][/bold cyan]"
    )
    console.print()

    if result.error:
        console.print(f"[red]✗ Error: {result.error}[/red]")
        return

    # Basic info
    info_table = Table(title="📋 Page Info", border_style="blue", show_lines=True)
    info_table.add_column("Property", style="bold")
    info_table.add_column("Value")
    info_table.add_row("Status Code", str(result.status_code))
    info_table.add_row("Title", result.title or "[dim]None[/dim]")
    info_table.add_row("Description", result.description[:200] or "[dim]None[/dim]")
    info_table.add_row("Links Found", str(len(result.links)))
    info_table.add_row("Images Found", str(len(result.images)))
    info_table.add_row("External Scripts", str(len(result.scripts)))
    info_table.add_row("Forms Found", str(len(result.forms)))
    console.print(info_table)

    # Emails
    if result.emails:
        console.print()
        console.print(Panel(
            "\n".join(result.emails),
            title=f"📧 Emails Found ({len(result.emails)})",
            border_style="green",
        ))

    # Phone numbers
    if result.phone_numbers:
        console.print()
        console.print(Panel(
            "\n".join(result.phone_numbers[:20]),
            title=f"📱 Phone Numbers ({len(result.phone_numbers)})",
            border_style="green",
        ))

    # Social Links
    if result.social_links:
        console.print()
        social_table = Table(title="🔗 Social Media Links", border_style="magenta")
        social_table.add_column("Platform", style="bold")
        social_table.add_column("URL", style="cyan")
        for sl in result.social_links:
            social_table.add_row(sl["platform"], sl["url"])
        console.print(social_table)

    # Technologies
    if result.technologies:
        console.print()
        tech_tree = Tree("🔧 Detected Technologies")
        for tech in result.technologies:
            tech_tree.add(f"[cyan]{tech}[/cyan]")
        console.print(tech_tree)


def dorks_to_dict(target: str, dorks: list[DorkQuery]) -> dict:
    """Convert dorks to serializable dict."""
    return {
        "module": "google_dorks",
        "target": target,
        "dorks": [
            {
                "name": d.name,
                "description": d.description,
                "query": d.query,
                "google_url": d.google_url,
            }
            for d in dorks
        ],
    }


def scrape_to_dict(result: ScrapeResult) -> dict:
    """Convert scrape result to serializable dict."""
    return {
        "module": "web_scrape",
        "url": result.url,
        "status_code": result.status_code,
        "title": result.title,
        "description": result.description,
        "emails": result.emails,
        "phone_numbers": result.phone_numbers,
        "social_links": result.social_links,
        "technologies": result.technologies,
        "links_count": len(result.links),
        "images_count": len(result.images),
        "forms_count": len(result.forms),
    }
