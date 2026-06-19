"""
parsers.py
----------
Parses PCAPDroid CSV exports and Burpsuite HTTP history XML exports
into a unified internal format consumed by the analysis engine.
"""

import base64
import csv
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# UNIFIED ROW  (internal format — output of both parsers)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RawRow:
    """
    One connection/request from either a PCAPDroid CSV or Burpsuite XML.
    Not all fields are populated by both parsers.
    """
    # Source
    source_type:    str = ""          # pcapdroid | burpsuite

    # Network
    domain:         str = ""
    dst_ip:         str = ""
    dst_port:       str = ""
    protocol:       str = ""

    # Traffic
    bytes_sent:     int = 0
    bytes_rcvd:     int = 0
    status:         str = ""          # Active | Error | Closed | etc.

    # Timing
    first_seen:     str = ""
    last_seen:      str = ""

    # HTTP (Burpsuite only, or PCAPDroid HTTP rows)
    method:         str = ""
    url:            str = ""
    request_body:   str = ""
    response_body:  str = ""
    http_status:    str = ""

    # DNS (PCAPDroid DNS rows)
    is_dns:         bool = False
    dns_query:      str = ""
    dns_resolver:   str = ""


# ─────────────────────────────────────────────────────────────────────────────
# PCAPDroid CSV PARSER
# ─────────────────────────────────────────────────────────────────────────────

# Expected PCAPDroid CSV columns (flexible — order may vary)
PCAP_REQUIRED_COLS = {"Info", "DstIp", "DstPort", "Proto", "BytesSent", "BytesRcvd", "Status"}

def parse_pcapdroid_csv(path: Path) -> list[RawRow]:
    """
    Parses a PCAPDroid CSV export.

    PCAPDroid CSV format (from PCAPDroid app → export):
        FirstSeen, LastSeen, Info, DstIp, DstPort, Proto,
        BytesSent, BytesRcvd, Status

    The Info field contains the domain name or IP:port string.
    DNS rows have Proto=DNS and Info = the queried domain name.
    """
    rows: list[RawRow] = []

    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)

        missing = PCAP_REQUIRED_COLS - set(reader.fieldnames or [])
        if missing:
            raise ValueError(
                f"PCAPDroid CSV missing columns: {missing}\n"
                f"Found: {reader.fieldnames}"
            )

        for raw in reader:
            proto     = raw.get("Proto", "").strip().upper()
            info      = raw.get("Info", "").strip()
            dst_ip    = raw.get("DstIp", "").strip()
            dst_port  = raw.get("DstPort", "").strip()
            status    = raw.get("Status", "").strip()

            try:
                bytes_sent = int(raw.get("BytesSent", 0) or 0)
                bytes_rcvd = int(raw.get("BytesRcvd", 0) or 0)
            except ValueError:
                bytes_sent, bytes_rcvd = 0, 0

            row = RawRow(
                source_type="pcapdroid",
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto,
                bytes_sent=bytes_sent,
                bytes_rcvd=bytes_rcvd,
                status=status,
                first_seen=raw.get("FirstSeen", "").strip(),
                last_seen=raw.get("LastSeen", "").strip(),
            )

            if proto == "DNS":
                # DNS row: Info = queried domain name, DstIp = resolver
                row.is_dns     = True
                row.dns_query  = _clean_domain(info)
                row.dns_resolver = dst_ip
                row.domain     = _clean_domain(info)
            else:
                # Connection row: Info = domain name (possibly with port)
                row.domain = _clean_domain(info)

            rows.append(row)

    return rows


def _clean_domain(info: str) -> str:
    """
    Extracts a clean domain name from a PCAPDroid Info field.
    Removes port suffixes, paths, and whitespace.
    Examples:
        "logs.ads.vungle.com:443"  →  "logs.ads.vungle.com"
        "192.168.1.1:9377"         →  "192.168.1.1"
        "example.com/path"         →  "example.com"
    """
    info = info.strip()
    info = info.split("/")[0]          # remove path
    info = re.sub(r":\d+$", "", info)  # remove :port
    return info.lower()


# ─────────────────────────────────────────────────────────────────────────────
# BURPSUITE XML PARSER
# ─────────────────────────────────────────────────────────────────────────────

def parse_burpsuite_xml(path: Path) -> list[RawRow]:
    """
    Parses a Burpsuite HTTP history XML export.

    Burpsuite XML structure:
        <items>
          <item>
            <url>...</url>
            <host ip="1.2.3.4">hostname</host>
            <port>443</port>
            <protocol>https</protocol>
            <method>POST</method>
            <request base64="true">...</request>
            <response base64="true">...</response>
            <status>200</status>
            ...
          </item>
        </items>
    """
    rows: list[RawRow] = []

    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except ET.ParseError as e:
        raise ValueError(f"Burpsuite XML parse error: {e}")

    for item in root.findall("item"):
        def txt(tag: str) -> str:
            el = item.find(tag)
            return (el.text or "").strip() if el is not None else ""

        host_el = item.find("host")
        host_ip = host_el.get("ip", "") if host_el is not None else ""
        host    = txt("host")
        port    = txt("port")
        proto   = txt("protocol").upper()
        method  = txt("method")
        url     = txt("url")
        status  = txt("status")

        # Decode base64 request/response
        req_body  = _decode_burp_field(item.find("request"))
        resp_body = _decode_burp_field(item.find("response"))

        # Approximate sizes from decoded bodies
        bytes_sent = len(req_body.encode("utf-8", errors="replace"))
        bytes_rcvd = len(resp_body.encode("utf-8", errors="replace"))

        row = RawRow(
            source_type="burpsuite",
            domain=host.lower(),
            dst_ip=host_ip,
            dst_port=port,
            protocol=proto or ("HTTPS" if port == "443" else "HTTP"),
            bytes_sent=bytes_sent,
            bytes_rcvd=bytes_rcvd,
            status=status,
            method=method,
            url=url,
            request_body=req_body,
            response_body=resp_body,
            http_status=status,
        )
        rows.append(row)

    return rows


def _decode_burp_field(element: Optional[ET.Element]) -> str:
    """Decode a Burpsuite base64 or plain field."""
    if element is None:
        return ""
    text = element.text or ""
    if element.get("base64") == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text
