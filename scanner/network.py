"""
🍄 MYCELIUM AGENT — Network Scanner v3 (Windows + Linux)
Skanuje sieć lokalną w poszukiwaniu urządzeń.
Kompatybilny z: Windows 10/11, Linux, macOS
"""

import subprocess
import socket
import concurrent.futures
import ipaddress
import platform
import re
import os
from datetime import datetime
from typing import List, Dict, Optional
from .device_types import identify_by_mac, identify_by_ports, identify_by_hostname, get_kingdom_info as get_device_info

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX   = platform.system() == "Linux"
IS_MAC     = platform.system() == "Darwin"


# ─── Własne IP ───────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ─── Sieć lokalna ─────────────────────────────────────────────────────────────

def get_local_network() -> str:
    """Wykrywa lokalną podsieć — działa na Windows i Linux."""
    local_ip = get_local_ip()

    if IS_WINDOWS:
        return _get_network_windows(local_ip)
    elif IS_LINUX:
        return _get_network_linux(local_ip)
    elif IS_MAC:
        return _get_network_mac(local_ip)

    # Fallback /24
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def _get_network_windows(local_ip: str) -> str:
    """Pobiera podsieć przez ipconfig na Windows."""
    try:
        result = subprocess.run(
            ["ipconfig"], capture_output=True, text=True,
            timeout=5, encoding="cp852", errors="replace"
        )
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if local_ip in line:
                # Szukamy maski podsieci w pobliskich liniach
                for j in range(max(0, i-5), min(len(lines), i+5)):
                    if "Maska" in lines[j] or "Subnet" in lines[j] or "mask" in lines[j].lower():
                        mask_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", lines[j])
                        if mask_match:
                            mask = mask_match.group(1)
                            try:
                                iface = ipaddress.IPv4Interface(f"{local_ip}/{mask}")
                                return str(iface.network)
                            except Exception:
                                pass
    except Exception:
        pass

    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def _get_network_linux(local_ip: str) -> str:
    """Pobiera podsieć przez 'ip addr' lub /proc na Linux."""
    try:
        result = subprocess.run(
            ["ip", "-o", "-f", "inet", "addr", "show"],
            capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 4 and local_ip in parts[3]:
                    return str(ipaddress.IPv4Interface(parts[3]).network)
    except Exception:
        pass

    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def _get_network_mac(local_ip: str) -> str:
    """Pobiera podsieć przez ifconfig na macOS."""
    try:
        result = subprocess.run(
            ["ifconfig"], capture_output=True, text=True, timeout=3
        )
        lines = result.stdout.splitlines()
        for i, line in enumerate(lines):
            if local_ip in line:
                mask_match = re.search(r"netmask\s+0x([0-9a-fA-F]+)", line)
                if mask_match:
                    mask_hex = int(mask_match.group(1), 16)
                    mask = socket.inet_ntoa(mask_hex.to_bytes(4, "big"))
                    iface = ipaddress.IPv4Interface(f"{local_ip}/{mask}")
                    return str(iface.network)
    except Exception:
        pass

    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


# ─── Tablica ARP ──────────────────────────────────────────────────────────────

def read_arp_table() -> Dict[str, str]:
    """Odczytuje tablicę ARP — Windows i Linux."""
    arp_map = {}

    if IS_WINDOWS:
        return _read_arp_windows()
    elif IS_LINUX:
        return _read_arp_linux()
    elif IS_MAC:
        return _read_arp_mac()

    return arp_map


def _read_arp_windows() -> Dict[str, str]:
    """Czyta ARP przez 'arp -a' na Windows."""
    arp_map = {}
    try:
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True,
            timeout=5, encoding="cp852", errors="replace"
        )
        for line in result.stdout.splitlines():
            # Format: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamiczny"
            match = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
                line
            )
            if match:
                ip  = match.group(1)
                mac = match.group(2).replace("-", ":").upper()
                arp_map[ip] = mac
    except Exception:
        pass
    return arp_map


def _read_arp_linux() -> Dict[str, str]:
    """Czyta ARP z /proc/net/arp na Linux."""
    arp_map = {}
    try:
        with open("/proc/net/arp", "r") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[2] == "0x2":
                    arp_map[parts[0]] = parts[3].upper()
        if arp_map:
            return arp_map
    except Exception:
        pass

    # Fallback: arp -n
    try:
        result = subprocess.run(["arp", "-n"], capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 3 and ":" in parts[2]:
                arp_map[parts[0]] = parts[2].upper()
    except Exception:
        pass

    return arp_map


def _read_arp_mac() -> Dict[str, str]:
    """Czyta ARP przez 'arp -a' na macOS."""
    arp_map = {}
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines():
            match = re.search(
                r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]{17})",
                line
            )
            if match:
                arp_map[match.group(1)] = match.group(2).upper()
    except Exception:
        pass
    return arp_map


# ─── Ping ─────────────────────────────────────────────────────────────────────

def ping_host(ip: str) -> Optional[int]:
    """Pinguje host. Zwraca TTL jeśli odpowiada, None jeśli nie."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", "800", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3,
                                encoding="cp852" if IS_WINDOWS else "utf-8",
                                errors="replace")
        if result.returncode == 0:
            match = re.search(r"[Tt][Tt][Ll]=(\d+)", result.stdout)
            return int(match.group(1)) if match else 64
        return None
    except Exception:
        return None


def ttl_to_os(ttl: int) -> str:
    """Zgaduje OS na podstawie TTL."""
    if ttl >= 128:
        return "windows"
    elif ttl >= 64:
        return "linux"
    elif ttl >= 255:
        return "network_device"
    return "unknown"


# ─── Hostname ─────────────────────────────────────────────────────────────────

def get_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ─── Skanowanie portów ────────────────────────────────────────────────────────

COMMON_PORTS = [
    22, 23, 53, 80, 135, 139, 443, 445, 554,
    548, 631, 1400, 1883, 1900, 3389, 5000,
    5001, 5555, 5900, 7000, 8001, 8002, 8080,
    8443, 8554, 9100, 62078
]


def scan_ports(ip: str, ports: List[int], timeout: float = 0.5) -> List[int]:
    """Skanuje porty współbieżnie."""

    def check(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port if result == 0 else None
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
        results = list(ex.map(check, ports))

    return [p for p in results if p is not None]


# ─── Skanowanie pojedynczego hosta ───────────────────────────────────────────

def scan_host(ip: str, local_ip: str, arp_table: Dict[str, str]) -> Optional[Dict]:
    is_self = (ip == local_ip)
    in_arp  = ip in arp_table

    ttl = ping_host(ip)

    if not is_self and ttl is None and not in_arp:
        return None

    if ttl is None and in_arp:
        ttl = 0

    mac        = arp_table.get(ip)
    hostname   = get_hostname(ip)
    open_ports = scan_ports(ip, COMMON_PORTS, timeout=0.5)
    guessed_os = ttl_to_os(ttl) if ttl and ttl > 0 else "unknown"
    status     = "online" if (ttl and ttl > 0) else "arp_only"

    # === IDENTYFIKACJA ===
    device_type = "unknown"

    if is_self:
        device_type = "windows_pc" if IS_WINDOWS else "linux_server"
        hostname    = hostname or "this-device"

    if device_type == "unknown" and mac:
        device_type = identify_by_mac(mac)

    if device_type == "unknown" and hostname:
        device_type = identify_by_hostname(hostname)

    if device_type == "unknown" and open_ports:
        device_type = identify_by_ports(open_ports, guessed_os)

    if device_type == "unknown" and guessed_os == "windows":
        device_type = "windows_pc"
    elif device_type == "unknown" and guessed_os == "linux":
        device_type = "linux_server"

    info = get_device_info(device_type)

    return {
        "ip":          ip,
        "mac":         mac or "—",
        "hostname":    hostname or ip,
        "device_type": device_type,
        "name":        info["name"],
        "emoji":       info["emoji"],
        "category":    info.get("category", "unknown"),
        "description": info.get("description", ""),
        "open_ports":  open_ports,
        "os_hint":     guessed_os,
        "ttl":         ttl,
        "actions":     info.get("actions", []),
        "discovered_at": datetime.now().isoformat(),
        "status":      status,
        "is_self":     is_self,
    }


# ─── Główny skaner ───────────────────────────────────────────────────────────

def scan_network(network: str = None, max_workers: int = 100) -> List[Dict]:
    """🍄 Odkrywa wszystkie aktywne urządzenia w sieci lokalnej."""
    if network is None:
        network = get_local_network()

    local_ip  = get_local_ip()
    print(f"🍄 Mycelium skanuje sieć: {network} (host: {local_ip})")
    print(f"   System: {platform.system()} {platform.release()}")

    arp_table = read_arp_table()
    if arp_table:
        print(f"  📋 Tablica ARP: {len(arp_table)} wpisów")

    hosts   = [str(ip) for ip in ipaddress.IPv4Network(network, strict=False).hosts()]
    devices = []
    scanned = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_host, ip, local_ip, arp_table): ip for ip in hosts}
        for future in concurrent.futures.as_completed(futures):
            scanned += 1
            try:
                result = future.result()
                if result:
                    devices.append(result)
                    tag = "🏠 [TEN HOST]" if result.get("is_self") else ""
                    print(f"  {result['emoji']} {result['ip']:<16} {result['name']:<25} {result.get('os_hint',''):<10} {tag}")
            except Exception:
                pass

            if scanned % 50 == 0 and scanned < len(hosts):
                print(f"  📡 {scanned}/{len(hosts)} adresów...")

    devices.sort(key=lambda d: [int(x) for x in d["ip"].split(".")])
    print(f"\n🍄 Skanowanie zakończone — znaleziono {len(devices)} urządzeń")
    return devices
