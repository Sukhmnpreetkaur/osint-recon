"""Username search across social media platforms."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

import aiohttp
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@dataclass
class UsernameResult:
    """Result of a username check on a single platform."""

    platform: str
    url: str
    found: bool
    status_code: int | None = None
    error: str | None = None


# Each entry: (platform_name, url_template, expected_status_on_found)
# {username} is replaced with the target username.
PLATFORMS: list[tuple[str, str, int]] = [
    # Social Media
    ("GitHub", "https://github.com/{username}", 200),
    ("Twitter/X", "https://x.com/{username}", 200),
    ("Instagram", "https://www.instagram.com/{username}/", 200),
    ("Reddit", "https://www.reddit.com/user/{username}", 200),
    ("TikTok", "https://www.tiktok.com/@{username}", 200),
    ("Pinterest", "https://www.pinterest.com/{username}/", 200),
    ("Tumblr", "https://{username}.tumblr.com", 200),
    ("Medium", "https://medium.com/@{username}", 200),
    ("Dev.to", "https://dev.to/{username}", 200),
    ("LinkedIn", "https://www.linkedin.com/in/{username}", 200),
    # Developer
    ("GitLab", "https://gitlab.com/{username}", 200),
    ("Bitbucket", "https://bitbucket.org/{username}/", 200),
    ("HackerRank", "https://www.hackerrank.com/{username}", 200),
    ("LeetCode", "https://leetcode.com/{username}/", 200),
    ("Codewars", "https://www.codewars.com/users/{username}", 200),
    ("Stack Overflow", "https://stackoverflow.com/users/{username}", 200),
    ("npm", "https://www.npmjs.com/~{username}", 200),
    ("PyPI", "https://pypi.org/user/{username}/", 200),
    ("Docker Hub", "https://hub.docker.com/u/{username}", 200),
    ("Replit", "https://replit.com/@{username}", 200),
    # Gaming
    ("Steam Community", "https://steamcommunity.com/id/{username}", 200),
    ("Twitch", "https://www.twitch.tv/{username}", 200),
    ("Roblox (via API)", "https://www.roblox.com/user.aspx?username={username}", 200),
    ("Chess.com", "https://www.chess.com/member/{username}", 200),
    # Creative
    ("Dribbble", "https://dribbble.com/{username}", 200),
    ("Behance", "https://www.behance.net/{username}", 200),
    ("DeviantArt", "https://www.deviantart.com/{username}", 200),
    ("SoundCloud", "https://soundcloud.com/{username}", 200),
    ("Spotify", "https://open.spotify.com/user/{username}", 200),
    ("Vimeo", "https://vimeo.com/{username}", 200),
    ("500px", "https://500px.com/p/{username}", 200),
    # Forums / Communities
    ("Hacker News", "https://news.ycombinator.com/user?id={username}", 200),
    ("Product Hunt", "https://www.producthunt.com/@{username}", 200),
    ("Keybase", "https://keybase.io/{username}", 200),
    ("About.me", "https://about.me/{username}", 200),
    ("Gravatar", "https://en.gravatar.com/{username}", 200),
    # Professional / Business
    ("Crunchbase", "https://www.crunchbase.com/person/{username}", 200),
    ("AngelList", "https://angel.co/u/{username}", 200),
    # Misc
    ("Flickr", "https://www.flickr.com/people/{username}/", 200),
    ("Patreon", "https://www.patreon.com/{username}", 200),
    ("Ko-fi", "https://ko-fi.com/{username}", 200),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{username}", 200),
    ("Linktree", "https://linktr.ee/{username}", 200),
    ("YouTube", "https://www.youtube.com/@{username}", 200),
    ("Telegram", "https://t.me/{username}", 200),
    ("Mastodon (mastodon.social)", "https://mastodon.social/@{username}", 200),
    ("Threads", "https://www.threads.net/@{username}", 200),
    ("Bluesky", "https://bsky.app/profile/{username}", 200),
    ("Substack", "https://{username}.substack.com", 200),
    ("Hashnode", "https://hashnode.com/@{username}", 200),
    ("Kaggle", "https://www.kaggle.com/{username}", 200),
    ("HuggingFace", "https://huggingface.co/{username}", 200),
]


async def _check_platform(
    session: aiohttp.ClientSession,
    username: str,
    platform: str,
    url_template: str,
    expected_status: int,
    semaphore: asyncio.Semaphore,
) -> UsernameResult:
    """Check if a username exists on a given platform."""
    url = url_template.replace("{username}", username)

    async with semaphore:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
                ssl=False,
            ) as response:
                found = response.status == expected_status

                # Extra heuristic: some sites return 200 but show a "not found" page
                if found and response.status == 200:
                    try:
                        body = await response.text(errors="replace")
                        body_lower = body.lower()
                        not_found_signals = [
                            "page not found",
                            "user not found",
                            "this account doesn't exist",
                            "sorry, this page",
                            "profile not found",
                            "nothing here",
                            "doesn't exist",
                            "404",
                        ]
                        if any(sig in body_lower for sig in not_found_signals):
                            # Only mark as not found if the signal is prominent
                            if len(body) < 50_000:
                                found = False
                    except Exception:
                        pass

                return UsernameResult(
                    platform=platform,
                    url=url,
                    found=found,
                    status_code=response.status,
                )
        except asyncio.TimeoutError:
            return UsernameResult(
                platform=platform, url=url, found=False, error="Timeout"
            )
        except Exception as exc:
            return UsernameResult(
                platform=platform, url=url, found=False, error=str(exc)[:80]
            )


async def search_username(
    username: str,
    max_concurrent: int = 20,
    timeout: float = 10.0,
) -> list[UsernameResult]:
    """Search for a username across all platforms."""
    semaphore = asyncio.Semaphore(max_concurrent)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=False)
    async with aiohttp.ClientSession(
        headers=headers, connector=connector
    ) as session:
        tasks = [
            _check_platform(session, username, name, url_tmpl, status, semaphore)
            for name, url_tmpl, status in PLATFORMS
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions that slipped through
    cleaned: list[UsernameResult] = []
    for r in results:
        if isinstance(r, UsernameResult):
            cleaned.append(r)
        elif isinstance(r, Exception):
            cleaned.append(
                UsernameResult(
                    platform="Unknown",
                    url="",
                    found=False,
                    error=str(r)[:80],
                )
            )
    return cleaned


def print_username_results(username: str, results: list[UsernameResult]) -> None:
    """Pretty-print username search results."""
    found = [r for r in results if r.found]
    not_found = [r for r in results if not r.found and not r.error]
    errors = [r for r in results if r.error]

    console.print()
    console.print(
        f"[bold cyan]🔍 Username Search Results for [yellow]'{username}'[/yellow][/bold cyan]"
    )
    console.print(f"[dim]Checked {len(results)} platforms[/dim]")
    console.print()

    if found:
        table = Table(title="✅ Found", border_style="green", show_lines=False)
        table.add_column("Platform", style="bold green")
        table.add_column("URL", style="cyan")
        table.add_column("Status", justify="center")
        for r in sorted(found, key=lambda x: x.platform):
            table.add_row(r.platform, r.url, str(r.status_code))
        console.print(table)
    else:
        console.print("[yellow]No matches found on any platform.[/yellow]")

    if errors:
        console.print()
        err_table = Table(
            title="⚠️  Errors / Timeouts", border_style="yellow", show_lines=False
        )
        err_table.add_column("Platform", style="yellow")
        err_table.add_column("Error", style="dim")
        for r in sorted(errors, key=lambda x: x.platform):
            err_table.add_row(r.platform, r.error or "Unknown")
        console.print(err_table)

    console.print()
    console.print(
        f"[bold]Summary:[/bold] "
        f"[green]{len(found)} found[/green] · "
        f"[red]{len(not_found)} not found[/red] · "
        f"[yellow]{len(errors)} errors[/yellow]"
    )


def results_to_dict(username: str, results: list[UsernameResult]) -> dict:
    """Convert results to a serializable dict."""
    return {
        "module": "username_search",
        "target": username,
        "total_checked": len(results),
        "found_count": sum(1 for r in results if r.found),
        "results": [
            {
                "platform": r.platform,
                "url": r.url,
                "found": r.found,
                "status_code": r.status_code,
                "error": r.error,
            }
            for r in results
        ],
    }
