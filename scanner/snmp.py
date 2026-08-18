"""
🍄 MYCELIUM — SNMP Scanner
Odpytuje urządzenia sieciowe przez SNMP v1/v2c.
Routery, switche, drukarki, NAS — ujawniają swoje sekrety przez community 'public'.
Działa bez dodatkowych bibliotek (czysty UDP).
"""

import socket
import struct
import time
from typing import Dict, List, Optional, Tuple


# Popularne OID do odpytywania
SNMP_OIDS = {
    "1.3.6.1.2.1.1.1.0":  "sysDescr",       # Opis systemu
    "1.3.6.1.2.1.1.5.0":  "sysName",         # Nazwa hosta
    "1.3.6.1.2.1.1.6.0":  "sysLocation",     # Lokalizacja
    "1.3.6.1.2.1.1.4.0":  "sysContact",      # Kontakt
    "1.3.6.1.2.1.2.1.0":  "ifNumber",        # Liczba interfejsów
}

# Community strings do próbowania
DEFAULT_COMMUNITIES = ["public", "private", "admin", "router", "manager"]


def _encode_oid(oid_str: str) -> bytes:
    """Koduje OID jako bytes ASN.1."""
    parts = [int(x) for x in oid_str.split(".")]
    encoded = bytes([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        if part < 128:
            encoded += bytes([part])
        else:
            # Multi-byte encoding
            result = []
            result.append(part & 0x7F)
            part >>= 7
            while part:
                result.append(0x80 | (part & 0x7F))
                part >>= 7
            encoded += bytes(reversed(result))
    return encoded


def _build_snmp_get(community: str, oid: str, request_id: int = 1) -> bytes:
    """Buduje pakiet SNMP GET Request."""
    # OID
    oid_bytes = _encode_oid(oid)
    oid_tlv = b"\x06" + bytes([len(oid_bytes)]) + oid_bytes
    
    # VarBind: SEQUENCE { OID, NULL }
    null_tlv = b"\x05\x00"
    varbind = b"\x30" + bytes([len(oid_tlv) + len(null_tlv)]) + oid_tlv + null_tlv
    
    # VarBindList
    varbindlist = b"\x30" + bytes([len(varbind)]) + varbind
    
    # Request ID
    rid = struct.pack(">I", request_id)
    rid_tlv = b"\x02\x04" + rid
    
    # Error status + error index
    error = b"\x02\x01\x00\x02\x01\x00"
    
    # PDU body
    pdu_body = rid_tlv + error + varbindlist
    
    # GetRequest PDU (0xA0)
    pdu = b"\xa0" + bytes([len(pdu_body)]) + pdu_body
    
    # Community
    community_bytes = community.encode("ascii")
    community_tlv = b"\x04" + bytes([len(community_bytes)]) + community_bytes
    
    # Version: 1 (SNMP v2c = 1)
    version = b"\x02\x01\x01"
    
    # Full message
    msg_body = version + community_tlv + pdu
    msg = b"\x30" + bytes([len(msg_body)]) + msg_body
    
    return msg


def _parse_snmp_response(data: bytes) -> Optional[str]:
    """Wyciąga wartość string z odpowiedzi SNMP."""
    try:
        # Szukamy OCTET STRING (0x04) lub INTEGER (0x02) w odpowiedzi
        i = 0
        while i < len(data) - 2:
            tag = data[i]
            if tag in (0x04, 0x02):  # OCTET STRING or INTEGER
                length = data[i + 1]
                if length & 0x80:  # long form
                    n_len_bytes = length & 0x7F
                    if i + 1 + n_len_bytes >= len(data):
                        break
                    length = int.from_bytes(data[i+2:i+2+n_len_bytes], "big")
                    value_start = i + 2 + n_len_bytes
                else:
                    value_start = i + 2
                
                value = data[value_start:value_start + length]
                
                if tag == 0x04 and len(value) > 2:
                    decoded = value.decode("utf-8", errors="replace").strip()
                    if decoded and not decoded.startswith("\x00"):
                        return decoded
                elif tag == 0x02 and len(value) > 0:
                    return str(int.from_bytes(value, "big"))
            i += 1
        return None
    except Exception:
        return None


def query_snmp(ip: str, oid: str, community: str = "public", timeout: float = 1.0) -> Optional[str]:
    """Wysyła pojedyncze zapytanie SNMP GET."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        packet = _build_snmp_get(community, oid)
        sock.sendto(packet, (ip, 161))
        
        data, _ = sock.recvfrom(4096)
        sock.close()
        
        return _parse_snmp_response(data)
    except Exception:
        return None


def scan_snmp_device(ip: str, timeout: float = 1.5) -> Optional[Dict]:
    """
    Próbuje zebrać informacje o urządzeniu przez SNMP.
    Testuje popularne community strings.
    """
    working_community = None
    
    for community in DEFAULT_COMMUNITIES:
        result = query_snmp(ip, "1.3.6.1.2.1.1.1.0", community, timeout=timeout)
        if result:
            working_community = community
            break
    
    if not working_community:
        return None
    
    # Zbierz dane
    info = {
        "ip": ip,
        "snmp_community": working_community,
        "snmp_accessible": True,
    }
    
    for oid, name in SNMP_OIDS.items():
        val = query_snmp(ip, oid, working_community, timeout=0.8)
        if val:
            info[name] = val
    
    # Klasyfikuj na podstawie sysDescr
    sys_descr = info.get("sysDescr", "").lower()
    sys_name = info.get("sysName", "")
    
    if any(x in sys_descr for x in ["cisco", "juniper", "routeros", "mikrotik"]):
        device_class = {"name": f"Router ({sys_name})", "emoji": "👑", "type": "router",
                        "category": "network", "kingdom": f"Cytadela {sys_name}"}
    elif any(x in sys_descr for x in ["linux", "debian", "ubuntu", "centos", "raspberry"]):
        device_class = {"name": f"Linux ({sys_name})", "emoji": "🗼", "type": "linux_server",
                        "category": "server", "kingdom": f"Forteca {sys_name}"}
    elif any(x in sys_descr for x in ["windows", "microsoft"]):
        device_class = {"name": f"Windows ({sys_name})", "emoji": "🏰", "type": "windows_pc",
                        "category": "computer", "kingdom": f"Zamek {sys_name}"}
    elif any(x in sys_descr for x in ["synology", "qnap", "nas", "diskstation"]):
        device_class = {"name": f"NAS ({sys_name})", "emoji": "💾", "type": "nas",
                        "category": "storage", "kingdom": f"Skarbiec {sys_name}"}
    elif any(x in sys_descr for x in ["printer", "laserjet", "hp", "epson"]):
        device_class = {"name": f"Drukarka ({sys_name})", "emoji": "🖨️", "type": "printer",
                        "category": "peripheral", "kingdom": f"Skryptorium {sys_name}"}
    else:
        device_class = {"name": sys_name or ip, "emoji": "📡", "type": "snmp_device",
                        "category": "network", "kingdom": f"Bastion SNMP {ip}"}
    
    info.update(device_class)
    info.update({
        "status": "online",
        "mac": "",
        "open_ports": [161],
        "discovery_method": "SNMP",
        "label": f"{device_class['emoji']} {device_class['kingdom']}",
        "actions": ["ping", "snmp_query"],
        "hostname": sys_name or "",
    })
    
    return info


def get_arp_table_via_snmp(router_ip: str, community: str = "public") -> List[Dict]:
    """
    Pobiera tablicę ARP routera przez SNMP.
    To pozwala odkryć urządzenia które nie odpowiadają na ping!
    OID: 1.3.6.1.2.1.4.22.1.2 — ipNetToMediaPhysAddress
    """
    devices = []
    
    # Próbujemy walk przez tablicę ARP
    # (uproszczona implementacja — tylko kilka wpisów)
    base_oid = "1.3.6.1.2.1.4.22.1.2"
    
    # Pobierz community jeśli nie podano
    if community == "public":
        for c in DEFAULT_COMMUNITIES:
            test = query_snmp(router_ip, "1.3.6.1.2.1.1.1.0", c, timeout=1.0)
            if test:
                community = c
                break
    
    # Próbuj kilka znanych indeksów tablicy ARP
    for i in range(1, 10):
        for j in range(1, 255):
            oid = f"{base_oid}.{i}.{j}"
            result = query_snmp(router_ip, oid, community, timeout=0.3)
            if result:
                devices.append({
                    "index": f"{i}.{j}",
                    "mac_raw": result,
                })
            if j > 5 and not devices:  # stop early if nothing found
                break
    
    return devices
