"""
🍄 MYCELIUM — NetBIOS/NBNS Scanner
Wykrywa Windows PC, Samba, NAS przez NetBIOS Name Service.
Działa na Windows i Linux bez dodatkowych narzędzi.
"""

import socket
import struct
import time
import concurrent.futures
from typing import List, Dict, Optional


def _build_nbns_query() -> bytes:
    """Buduje pakiet zapytania NetBIOS Name Service (broadcast)."""
    # Transaction ID
    txid = struct.pack(">H", 0x1234)
    # Flags: Standard query, broadcast
    flags = struct.pack(">H", 0x0110)
    # QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    counts = struct.pack(">HHHH", 1, 0, 0, 0)
    # Query for *, NBSTAT, IN
    name = b"\x20" + b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + b"\x00"
    qtype = struct.pack(">H", 0x0021)  # NBSTAT
    qclass = struct.pack(">H", 0x0001)  # IN
    return txid + flags + counts + name + qtype + qclass


def _parse_nbns_response(data: bytes) -> Optional[dict]:
    """Parsuje odpowiedź NetBIOS i wyciąga nazwy."""
    try:
        if len(data) < 57:
            return None
        
        # Jump to name entries
        # Fixed offset after header + name (34 bytes) + type/class/ttl/rdlength
        offset = 56  # After name + header
        
        if offset >= len(data):
            return None
        
        num_names = data[offset]
        offset += 1
        
        names = []
        for _ in range(min(num_names, 20)):
            if offset + 18 > len(data):
                break
            raw_name = data[offset:offset+15].decode("ascii", errors="replace").rstrip()
            name_type = data[offset+15]
            flags = struct.unpack(">H", data[offset+16:offset+18])[0]
            offset += 18
            
            if raw_name.strip():
                names.append({
                    "name": raw_name.strip(),
                    "type": name_type,
                    "group": bool(flags & 0x8000),
                })
        
        # Extract computer name (type 0x00, not group)
        computer_name = None
        workgroup = None
        for n in names:
            if n["type"] == 0x00 and not n["group"] and not computer_name:
                computer_name = n["name"]
            elif n["type"] == 0x00 and n["group"] and not workgroup:
                workgroup = n["name"]
        
        return {
            "computer_name": computer_name,
            "workgroup": workgroup,
            "all_names": names,
        }
    except Exception:
        return None


def query_nbns(ip: str, timeout: float = 1.0) -> Optional[dict]:
    """Wysyła zapytanie NetBIOS do konkretnego IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        query = _build_nbns_query()
        sock.sendto(query, (ip, 137))
        
        data, _ = sock.recvfrom(1024)
        result = _parse_nbns_response(data)
        sock.close()
        return result
    except Exception:
        return None


def scan_netbios_broadcast(subnet: str = None, timeout: float = 2.0) -> List[Dict]:
    """
    Wysyła broadcast NetBIOS i zbiera odpowiedzi.
    Wykrywa Windows PC, Samba NAS i inne urządzenia NetBIOS.
    """
    devices = {}
    
    NBNS_PORT = 137
    BROADCAST = "255.255.255.255"
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.bind(("", 0))
        
        query = _build_nbns_query()
        sock.sendto(query, (BROADCAST, NBNS_PORT))
        
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(1024)
                ip = addr[0]
                if ip == "127.0.0.1" or ip in devices:
                    continue
                    
                result = _parse_nbns_response(data)
                if result and result.get("computer_name"):
                    name = result["computer_name"]
                    workgroup = result.get("workgroup", "WORKGROUP")
                    
                    devices[ip] = {
                        "ip": ip,
                        "hostname": name,
                        "netbios_name": name,
                        "workgroup": workgroup,
                        "mac": "",
                        "status": "online",
                        "open_ports": [139, 445],
                        "discovery_method": "NetBIOS",
                        "name": f"Windows PC ({name})",
                        "emoji": "🏰",
                        "type": "windows_pc",
                        "category": "computer",
                        "label": f"🏰 Zamek {name}",
                        "kingdom": f"Zamek {name}",
                        "actions": ["ping", "http_get", "wake_on_lan"],
                    }
            except socket.timeout:
                break
            except Exception:
                continue
        
        sock.close()
        
    except Exception as e:
        print(f"  ⚠️ NetBIOS broadcast: {e}")
    
    result = list(devices.values())
    if result:
        print(f"  🏰 NetBIOS: znaleziono {len(result)} urządzeń Windows/Samba")
    
    return result


def enrich_with_netbios(devices: List[Dict]) -> List[Dict]:
    """
    Próbuje uzyskać nazwy NetBIOS dla znanych urządzeń.
    Wzbogaca istniejące urządzenia o nazwy komputerów.
    """
    windows_ips = [
        d["ip"] for d in devices
        if d.get("type") == "windows_pc" or 445 in d.get("open_ports", []) or 139 in d.get("open_ports", [])
    ]
    
    if not windows_ips:
        return devices
    
    enriched = {d["ip"]: d for d in devices}
    
    def query_one(ip):
        result = query_nbns(ip, timeout=0.8)
        return ip, result
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = {pool.submit(query_one, ip): ip for ip in windows_ips}
        for f in concurrent.futures.as_completed(futures, timeout=5):
            try:
                ip, result = f.result()
                if result and result.get("computer_name") and ip in enriched:
                    name = result["computer_name"]
                    enriched[ip]["netbios_name"] = name
                    enriched[ip]["hostname"] = enriched[ip].get("hostname") or name
                    enriched[ip]["label"] = f"🏰 Zamek {name}"
                    enriched[ip]["kingdom"] = f"Zamek {name}"
            except Exception:
                pass
    
    return list(enriched.values())
