"""Metadata extraction from files — EXIF from images, PDF metadata, document properties."""

from __future__ import annotations

import os
import json
from dataclasses import dataclass, field
from typing import Any, Optional
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


@dataclass
class MetadataResult:
    """File metadata extraction result."""

    filepath: str
    file_type: str = ""
    file_size: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    gps_coordinates: tuple[float, float] | None = None
    gps_map_url: str | None = None
    errors: list[str] = field(default_factory=list)


def _get_exif_data(filepath: str) -> tuple[dict[str, Any], tuple[float, float] | None]:
    """Extract EXIF data from an image file."""
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS

    metadata: dict[str, Any] = {}
    gps_coords: tuple[float, float] | None = None

    try:
        img = Image.open(filepath)
        metadata["format"] = img.format
        metadata["mode"] = img.mode
        metadata["size"] = f"{img.size[0]}x{img.size[1]}"

        exif_data = img._getexif()
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = TAGS.get(tag_id, tag_id)

                # Handle GPS data
                if tag_name == "GPSInfo":
                    gps_info = {}
                    for gps_tag_id, gps_value in value.items():
                        gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_info[gps_tag_name] = gps_value
                    metadata["GPSInfo"] = {
                        k: str(v) for k, v in gps_info.items()
                    }

                    # Calculate coordinates
                    try:
                        lat = gps_info.get("GPSLatitude")
                        lat_ref = gps_info.get("GPSLatitudeRef")
                        lon = gps_info.get("GPSLongitude")
                        lon_ref = gps_info.get("GPSLongitudeRef")

                        if lat and lon:
                            lat_deg = float(lat[0]) + float(lat[1]) / 60 + float(lat[2]) / 3600
                            lon_deg = float(lon[0]) + float(lon[1]) / 60 + float(lon[2]) / 3600
                            if lat_ref == "S":
                                lat_deg = -lat_deg
                            if lon_ref == "W":
                                lon_deg = -lon_deg
                            gps_coords = (lat_deg, lon_deg)
                    except (TypeError, IndexError, ValueError):
                        pass
                elif isinstance(value, bytes):
                    metadata[str(tag_name)] = f"<binary data, {len(value)} bytes>"
                else:
                    try:
                        json.dumps(value)  # Test serializability
                        metadata[str(tag_name)] = value
                    except (TypeError, ValueError):
                        metadata[str(tag_name)] = str(value)

        img.close()
    except Exception as exc:
        metadata["_error"] = str(exc)

    return metadata, gps_coords


def _get_pdf_metadata(filepath: str) -> dict[str, Any]:
    """Extract metadata from a PDF file."""
    from PyPDF2 import PdfReader

    metadata: dict[str, Any] = {}

    try:
        reader = PdfReader(filepath)
        metadata["num_pages"] = len(reader.pages)

        info = reader.metadata
        if info:
            for key in ["/Title", "/Author", "/Subject", "/Creator", "/Producer",
                        "/CreationDate", "/ModDate", "/Keywords"]:
                val = info.get(key)
                if val:
                    metadata[key.lstrip("/")] = str(val)

        # Check for encryption
        metadata["encrypted"] = reader.is_encrypted

        # Check for forms
        if "/AcroForm" in reader.trailer.get("/Root", {}):
            metadata["has_forms"] = True

    except Exception as exc:
        metadata["_error"] = str(exc)

    return metadata


def _get_generic_metadata(filepath: str) -> dict[str, Any]:
    """Get basic file system metadata for any file."""
    metadata: dict[str, Any] = {}
    stat = os.stat(filepath)

    from datetime import datetime

    metadata["filename"] = os.path.basename(filepath)
    metadata["extension"] = os.path.splitext(filepath)[1]
    metadata["size_bytes"] = stat.st_size
    metadata["size_human"] = _human_size(stat.st_size)
    metadata["created"] = datetime.fromtimestamp(stat.st_ctime).isoformat()
    metadata["modified"] = datetime.fromtimestamp(stat.st_mtime).isoformat()
    metadata["accessed"] = datetime.fromtimestamp(stat.st_atime).isoformat()

    return metadata


def _human_size(nbytes: int) -> str:
    """Convert bytes to human-readable size."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if nbytes < 1024.0:
            return f"{nbytes:.1f} {unit}"
        nbytes /= 1024.0
    return f"{nbytes:.1f} PB"


def _detect_file_type(filepath: str) -> str:
    """Detect file type from extension."""
    ext = os.path.splitext(filepath)[1].lower()
    type_map = {
        ".jpg": "image", ".jpeg": "image", ".png": "image", ".gif": "image",
        ".bmp": "image", ".tiff": "image", ".tif": "image", ".webp": "image",
        ".heic": "image", ".heif": "image", ".raw": "image", ".cr2": "image",
        ".nef": "image", ".svg": "image",
        ".pdf": "pdf",
        ".doc": "document", ".docx": "document", ".odt": "document",
        ".xls": "spreadsheet", ".xlsx": "spreadsheet", ".ods": "spreadsheet",
        ".ppt": "presentation", ".pptx": "presentation", ".odp": "presentation",
        ".mp3": "audio", ".wav": "audio", ".flac": "audio", ".ogg": "audio",
        ".mp4": "video", ".avi": "video", ".mkv": "video", ".mov": "video",
    }
    return type_map.get(ext, "unknown")


def extract_metadata(filepath: str) -> MetadataResult:
    """Extract metadata from a file."""
    filepath = str(Path(filepath).resolve())
    result = MetadataResult(filepath=filepath)

    if not os.path.isfile(filepath):
        result.errors.append(f"File not found: {filepath}")
        return result

    result.file_size = os.path.getsize(filepath)
    result.file_type = _detect_file_type(filepath)

    # Always get filesystem metadata
    fs_meta = _get_generic_metadata(filepath)
    result.metadata.update(fs_meta)

    # Type-specific extraction
    if result.file_type == "image":
        exif_meta, gps = _get_exif_data(filepath)
        result.metadata.update(exif_meta)
        if gps:
            result.gps_coordinates = gps
            result.gps_map_url = (
                f"https://www.google.com/maps?q={gps[0]},{gps[1]}"
            )
    elif result.file_type == "pdf":
        pdf_meta = _get_pdf_metadata(filepath)
        result.metadata.update(pdf_meta)

    return result


def print_metadata_results(result: MetadataResult) -> None:
    """Pretty-print metadata extraction results."""
    console.print()
    console.print(
        f"[bold cyan]📄 Metadata for [yellow]{os.path.basename(result.filepath)}[/yellow][/bold cyan]"
    )
    console.print(f"[dim]{result.filepath}[/dim]")
    console.print()

    if result.errors:
        for err in result.errors:
            console.print(f"[red]✗ {err}[/red]")
        return

    table = Table(title=f"📋 {result.file_type.upper()} Metadata", border_style="blue", show_lines=True)
    table.add_column("Property", style="bold", max_width=30)
    table.add_column("Value", max_width=80)

    for key, value in result.metadata.items():
        if key.startswith("_"):
            continue
        if isinstance(value, dict):
            val_str = json.dumps(value, indent=2, default=str)
        elif isinstance(value, list):
            val_str = ", ".join(str(v) for v in value)
        else:
            val_str = str(value)
        table.add_row(key, val_str[:200])

    console.print(table)

    # GPS info
    if result.gps_coordinates:
        lat, lon = result.gps_coordinates
        console.print()
        console.print(
            Panel(
                f"[bold green]Latitude:[/bold green]  {lat:.6f}\n"
                f"[bold green]Longitude:[/bold green] {lon:.6f}\n"
                f"[bold blue]Google Maps:[/bold blue] {result.gps_map_url}",
                title="📍 GPS Location Found!",
                border_style="red",
            )
        )


def results_to_dict(result: MetadataResult) -> dict:
    """Convert to serializable dict."""
    data: dict[str, Any] = {
        "module": "metadata_extraction",
        "filepath": result.filepath,
        "file_type": result.file_type,
        "file_size": result.file_size,
        "metadata": {},
        "gps_coordinates": None,
        "gps_map_url": result.gps_map_url,
    }
    # Ensure serializable
    for k, v in result.metadata.items():
        try:
            json.dumps(v, default=str)
            data["metadata"][k] = v
        except (TypeError, ValueError):
            data["metadata"][k] = str(v)

    if result.gps_coordinates:
        data["gps_coordinates"] = {
            "latitude": result.gps_coordinates[0],
            "longitude": result.gps_coordinates[1],
        }
    return data
