"""
🍄 MYCELIUM AGENT — Powerline / PLC Scanner
Wykrywa urządzenia sieciowe podłączone przez kable elektryczne (HomePlug AV/AV2, G.hn)
Producenci: TP-Link, devolo, Netgear, D-Link, ZyXEL, Zyxel, Tenda, TRENDnet
"""

import socket
import struct
import subprocess
import platform
import re
from typing import Dict, List, Optional
from datetime import datetime

# ─────────────────────────────────────────────────────────────────────────────
# MAC OUI — prefiksy producentów adapterów Powerline
# ─────────────────────────────────────────────────────────────────────────────

POWERLINE_MAC_OUI: Dict[str, Dict] = {
    # TP-Link Powerline (TL-PAxxxx, TL-WPAxxxx)
    "50:C7:BF": {"vendor": "TP-Link", "model": "Powerline AV"},
    "C0:4A:00": {"vendor": "TP-Link", "model": "Powerline AV500"},
    "B0:95:75": {"vendor": "TP-Link", "model": "Powerline AV600"},
    "F4:F2:6D": {"vendor": "TP-Link", "model": "Powerline AV1000"},
    "30:DE:4B": {"vendor": "TP-Link", "model": "Powerline WiFi"},
    "A0:F3:C1": {"vendor": "TP-Link", "model": "Powerline AV2"},
    "98:DA:C4": {"vendor": "TP-Link", "model": "Powerline TL-PA"},

    # devolo dLAN (najpopularniejsze w Europie)
    "00:0B:3B": {"vendor": "devolo", "model": "dLAN"},
    "BC:F2:AF": {"vendor": "devolo", "model": "dLAN 550"},
    "00:13:E8": {"vendor": "devolo", "model": "dLAN 200"},
    "78:D6:F0": {"vendor": "devolo", "model": "dLAN 1200+"},
    "00:24:A0": {"vendor": "devolo", "model": "dLAN AV"},
    "44:D4:37": {"vendor": "devolo", "model": "dLAN Magic"},
    "C0:E4:22": {"vendor": "devolo", "model": "dLAN 500"},

    # Netgear Powerline
    "00:09:AB": {"vendor": "Netgear", "model": "Powerline XAV"},
    "20:4E:7F": {"vendor": "Netgear", "model": "Powerline PL1000"},
    "C4:04:15": {"vendor": "Netgear", "model": "Powerline AV+"},

    # D-Link Powerline
    "00:17:9A": {"vendor": "D-Link", "model": "Powerline DHP"},
    "28:10:7B": {"vendor": "D-Link", "model": "Powerline AV2"},
    "14:D6:4D": {"vendor": "D-Link", "model": "Powerline DHP-600AV"},

    # ZyXEL / Zyxel Powerline
    "00:13:49": {"vendor": "ZyXEL", "model": "Powerline PLA"},
    "E0:91:F5": {"vendor": "ZyXEL", "model": "Powerline PLA5206"},
    "A8:A6:EE": {"vendor": "Zyxel", "model": "Powerline PLA5405"},

    # Tenda Powerline
    "C8:3A:35": {"vendor": "Tenda", "model": "Powerline PA"},
    "00:0C:43": {"vendor": "Tenda", "model": "Powerline AV"},

    # TRENDnet Powerline
    "00:14:D1": {"vendor": "TRENDnet", "model": "Powerline TPL"},
    "00:18:E7": {"vendor": "TRENDnet", "model": "Powerline AV"},

    # Comtrend Powerline
    "00:08:A2": {"vendor": "Comtrend", "model": "Powerline PG"},

    # Solwise / Billion Powerline
    "00:1E:58": {"vendor": "Solwise/Billion", "model": "Powerline"},

    # HomePlug generyczne
    "00:1F:C6": {"vendor": "Atheros/Qualcomm", "model": "HomePlug AV chipset"},
    "00:26:44": {"vendor": "Atheros/Qualcomm", "model": "HomePlug AV2 chipset"},

    # Belkin Powerline
    "94:10:3E": {"vendor": "Belkin", "model": "Powerline"},
}

# ─────────────────────────────────────────────────────────────────────────────
# Porty charakterystyczne dla adapterów Powerline
# ─────────────────────────────────────────────────────────────────────────────

POWERLINE_PORTS = [
    80,     # HTTP zarządzanie
    443,    # HTTPS zarządzanie
    8080,   # HTTP alternatywny
    7547,   # TR-069 (zdalne zarządzanie przez ISP)
    9999,   # TP-Link management
    1080,   # devolo management
]

# ─────────────────────────────────────────────────────────────────────────────
# Słowa kluczowe w hostname sugerujące Powerline
# ─────────────────────────────────────────────────────────────────────────────

POWERLINE_HOSTNAME_KEYWORDS = [
    "powerline", "devolo", "dlan", "homeplug",
    "tl-pa", "tl-wpa", "xav", "dhp", "pla",
    "plc", "av500", "av600", "av1000", "av2",
    "magic", "tpl-",
]


def normalize_mac(mac: str) -> str:
    """Normalizuje MAC do formatu AA:BB:CC"""
    mac = mac.upper().replace("-", ":").replace(".", ":")
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(parts)
    return mac


def get_mac_oui(mac: str) -> str:
    """Zwraca pierwsze 3 oktety MAC (OUI)"""
    normalized = normalize_mac(mac)
    parts = normalized.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


def identify_powerline_by_mac(mac: str) -> Optional[Dict]:
    """Sprawdza czy MAC należy do adaptera Powerline"""
    if not mac:
        return None
    oui = get_mac_oui(mac)
    return POWERLINE_MAC_OUI.get(oui)


def scan_upnp_powerline(timeout: float = 3.0) -> List[Dict]:
    """
    Wykrywa urządzenia Powerline przez UPnP/SSDP multicast.
    Powerline adaptery często ogłaszają się przez UPnP.
    """
    devices = []
    SSDP_ADDR = "239.255.255.250"
    SSDP_PORT = 1900
    SSDP_MX = 2

    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
        "MAN: \"ssdp:discover\"\r\n"
        f"MX: {SSDP_MX}\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    )

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(timeout)
        sock.sendto(ssdp_request.encode(), (SSDP_ADDR, SSDP_PORT))

        seen_ips = set()
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                if ip in seen_ips:
                    continue
                seen_ips.add(ip)

                response = data.decode("utf-8", errors="ignore")
                device_info = {
                    "ip": ip,
                    "protocol": "UPnP/SSDP",
                    "raw": response[:500],
                }

                # Sprawdź czy to Powerline po treści odpowiedzi
                response_lower = response.lower()
                for kw in POWERLINE_HOSTNAME_KEYWORDS:
                    if kw in response_lower:
                        device_info["powerline_hint"] = kw
                        break

                # Wyciągnij SERVER lub LOCATION
                for line in response.split("\r\n"):
                    if line.lower().startswith("server:"):
                        device_info["server"] = line.split(":", 1)[1].strip()
                    elif line.lower().startswith("location:"):
                        device_info["location"] = line.split(":", 1)[1].strip()

                devices.append(device_info)

            except socket.timeout:
                break

    except Exception as e:
        pass
    finally:
        try:
            sock.close()
        except:
            pass

    return devices


def check_powerline_web_interface(ip: str, timeout: float = 2.0) -> Optional[Dict]:
    """
    Sprawdza czy host ma webowy interfejs zarządzania adaptera Powerline.
    TP-Link: port 80, ścieżka /index.htm
    devolo: port 80, szuka 'devolo' w treści
    """
    import urllib.request
    import urllib.error

    for port in [80, 8080, 443]:
        protocol = "https" if port == 443 else "http"
        url = f"{protocol}://{ip}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mycelium/1.0"})
            ctx = None
            if protocol == "https":
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(2048).decode("utf-8", errors="ignore").lower()
                server = resp.headers.get("Server", "")

                for kw in ["devolo", "powerline", "homeplug", "tl-pa", "tl-wpa",
                           "dlan", "plc adapter", "av500", "av600", "av1000"]:
                    if kw in body or kw in server.lower():
                        return {
                            "port": port,
                            "url": url,
                            "keyword_found": kw,
                            "server": server,
                        }
        except Exception:
            continue

    return None


def classify_device_as_powerline(
    mac: str,
    hostname: str,
    open_ports: List[int],
    upnp_hint: Optional[str] = None,
    web_hint: Optional[Dict] = None,
) -> Dict:
    """
    Ocenia prawdopodobieństwo że urządzenie to adapter Powerline.
    Zwraca: {"is_powerline": bool, "confidence": int, "vendor": str, "evidence": [str]}
    """
    confidence = 0
    evidence = []
    vendor = "Nieznany"
    model = ""

    # Sprawdź MAC OUI — najsilniejszy sygnał
    powerline_mac = identify_powerline_by_mac(mac)
    if powerline_mac:
        confidence += 90
        vendor = powerline_mac["vendor"]
        model = powerline_mac["model"]
        evidence.append(f"MAC OUI pasuje do {vendor} {model}")

    # Sprawdź hostname
    hostname_lower = hostname.lower() if hostname else ""
    for kw in POWERLINE_HOSTNAME_KEYWORDS:
        if kw in hostname_lower:
            confidence += 40
            evidence.append(f"Hostname zawiera '{kw}'")
            break

    # UPnP hint
    if upnp_hint:
        confidence += 30
        evidence.append(f"UPnP odpowiedź zawiera '{upnp_hint}'")

    # Web interface hint
    if web_hint:
        confidence += 50
        evidence.append(f"Webowy interfejs zawiera '{web_hint.get('keyword_found')}' na porcie {web_hint.get('port')}")

    return {
        "is_powerline": confidence >= 40,
        "confidence": min(confidence, 100),
        "vendor": vendor,
        "model": model,
        "evidence": evidence,
    }


def scan_powerline_devices(devices_from_network: List[Dict]) -> List[Dict]:
    """
    Główna funkcja — analizuje urządzenia z skanowania sieci
    i oznacza/wykrywa adaptery Powerline.
    """
    powerline_devices = []

    # 1. Skanuj UPnP
    print("  ⚡ UPnP/SSDP multicast — szukam adapterów Powerline...")
    upnp_results = scan_upnp_powerline(timeout=3.0)
    upnp_by_ip: Dict[str, Dict] = {}
    for u in upnp_results:
        ip = u.get("ip", "")
        if ip:
            upnp_by_ip[ip] = u
    if upnp_results:
        print(f"  ⚡ UPnP: znaleziono {len(upnp_results)} odpowiedzi")

    # 2. Sprawdź każde urządzenie z sieci
    for dev in devices_from_network:
        ip = dev.get("ip", "")
        mac = dev.get("mac", "")
        hostname = dev.get("hostname", "")
        open_ports = dev.get("open_ports", [])

        upnp_hint = None
        if ip in upnp_by_ip:
            upnp_hint = upnp_by_ip[ip].get("powerline_hint")

        classification = classify_device_as_powerline(
            mac=mac,
            hostname=hostname,
            open_ports=open_ports,
            upnp_hint=upnp_hint,
        )

        if classification["is_powerline"]:
            powerline_device = {
                **dev,
                "device_type": "powerline_adapter",
                "category": "powerline",
                "emoji": "⚡",
                "vendor": classification["vendor"],
                "model": classification["model"],
                "powerline_confidence": classification["confidence"],
                "powerline_evidence": classification["evidence"],
                "name": f"{classification['vendor']} Powerline",
                "discovered_at": datetime.now().isoformat(),
            }
            powerline_devices.append(powerline_device)
            print(f"  ⚡ {ip}  {classification['vendor']} {classification['model']}  "
                  f"pewność: {classification['confidence']}%  "
                  f"({', '.join(classification['evidence'])})")

    # 3. Dodaj urządzenia znalezione przez UPnP ale nie w sieci
    network_ips = {d.get("ip") for d in devices_from_network}
    for ip, upnp in upnp_by_ip.items():
        if ip not in network_ips and upnp.get("powerline_hint"):
            powerline_devices.append({
                "ip": ip,
                "mac": "unknown",
                "hostname": upnp.get("server", ""),
                "device_type": "powerline_adapter",
                "category": "powerline",
                "emoji": "⚡",
                "vendor": "Powerline",
                "model": "HomePlug AV",
                "powerline_confidence": 60,
                "powerline_evidence": [f"UPnP hint: {upnp.get('powerline_hint')}"],
                "name": "Powerline Adapter (UPnP)",
                "open_ports": [],
                "discovered_at": datetime.now().isoformat(),
                "status": "online",
                "discovery_method": "upnp_only",
            })

    return powerline_devices


# Eksport do device_types.py
POWERLINE_DEVICE_TYPE = {
    "powerline_adapter": {
        "name": "Adapter Powerline",
        "emoji": "⚡",
        "category": "powerline",
        "ports": [80, 443, 8080, 7547],
        "ports_required": 0,
        "mac_oui": list(POWERLINE_MAC_OUI.keys()),
        "actions": ["ping", "web_config", "powerline_status"],
        "description": "Adapter sieciowy przez sieć elektryczną (HomePlug AV/AV2, G.hn)",
    }
}
