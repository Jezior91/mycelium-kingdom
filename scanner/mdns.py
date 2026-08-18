"""
🍄 MYCELIUM — mDNS/Bonjour Scanner
Odkrywa urządzenia Apple, smart speakers, drukarki, NAS i inne
przez multicast DNS (Zeroconf/Bonjour).
Działa na Windows i Linux bez dodatkowego oprogramowania.
"""

import socket
import struct
import time
import platform
from typing import List, Dict

# Znane typy serwisów mDNS i ich znaczenie
MDNS_SERVICES = {
    "_airplay._tcp.local":     {"name": "AirPlay",        "emoji": "🍎", "type": "apple_tv",     "category": "media"},
    "_raop._tcp.local":        {"name": "AirTunes",       "emoji": "🎵", "type": "apple_tv",     "category": "media"},
    "_companion-link._tcp.local": {"name": "Apple TV",    "emoji": "📺", "type": "apple_tv",     "category": "media"},
    "_googlecast._tcp.local":  {"name": "Chromecast",     "emoji": "📡", "type": "chromecast",   "category": "media"},
    "_spotify-connect._tcp.local": {"name": "Spotify Connect", "emoji": "🎶", "type": "speaker", "category": "media"},
    "_amzn-wplay._tcp.local":  {"name": "Amazon Echo",    "emoji": "🔊", "type": "echo",         "category": "smart_home"},
    "_hap._tcp.local":         {"name": "HomeKit",        "emoji": "🏠", "type": "homekit",      "category": "smart_home"},
    "_hue._tcp.local":         {"name": "Philips Hue",    "emoji": "💡", "type": "philips_hue",  "category": "smart_home"},
    "_http._tcp.local":        {"name": "Web Interface",  "emoji": "🌐", "type": "web_device",   "category": "network"},
    "_smb._tcp.local":         {"name": "Samba/SMB",      "emoji": "📁", "type": "nas",          "category": "storage"},
    "_afpovertcp._tcp.local":  {"name": "AFP (Mac Share)","emoji": "🍎", "type": "mac_pc",       "category": "computer"},
    "_printer._tcp.local":     {"name": "Drukarka",       "emoji": "🖨️", "type": "printer",      "category": "peripheral"},
    "_ipp._tcp.local":         {"name": "Drukarka IPP",   "emoji": "🖨️", "type": "printer",      "category": "peripheral"},
    "_pdl-datastream._tcp.local": {"name": "Drukarka PDL","emoji": "🖨️", "type": "printer",      "category": "peripheral"},
    "_nfs._tcp.local":         {"name": "NFS Share",      "emoji": "💾", "type": "nas",          "category": "storage"},
    "_ssh._tcp.local":         {"name": "SSH",            "emoji": "🔐", "type": "linux_server", "category": "server"},
    "_sftp-ssh._tcp.local":    {"name": "SFTP",           "emoji": "🔐", "type": "linux_server", "category": "server"},
    "_homeassistant._tcp.local": {"name": "Home Assistant","emoji": "🏡", "type": "home_assistant","category": "smart_home"},
    "_mqtt._tcp.local":        {"name": "MQTT Broker",    "emoji": "📨", "type": "mqtt_broker",  "category": "iot"},
    "_esphome._tcp.local":     {"name": "ESPHome",        "emoji": "⚡", "type": "esp_device",   "category": "iot"},
    "_workstation._tcp.local": {"name": "Stacja robocza", "emoji": "🖥️", "type": "linux_pc",     "category": "computer"},
    "_device-info._tcp.local": {"name": "Device Info",    "emoji": "ℹ️", "type": "unknown",      "category": "other"},
    "_sleep-proxy._udp.local": {"name": "Sleep Proxy",    "emoji": "💤", "type": "apple_device", "category": "computer"},
    "_daap._tcp.local":        {"name": "iTunes Share",   "emoji": "🎵", "type": "itunes",       "category": "media"},
    "_atc._tcp.local":         {"name": "AirTrack",       "emoji": "📡", "type": "apple_device", "category": "media"},
    "_nvstream._tcp.local":    {"name": "NVIDIA Shield",  "emoji": "🎮", "type": "nvidia_shield","category": "gaming"},
    "_axis-video._tcp.local":  {"name": "Axis Camera",    "emoji": "📷", "type": "ip_camera",    "category": "security"},
    "_rtsp._tcp.local":        {"name": "RTSP Camera",    "emoji": "📷", "type": "ip_camera",    "category": "security"},
}


def _build_mdns_query(service_type: str) -> bytes:
    """Buduje pakiet zapytania mDNS."""
    # DNS header: ID=0, QR=0 (query), OPCODE=0, AA=0, TC=0, RD=0, RA=0
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    
    # Encode service type as DNS labels
    labels = b""
    for part in service_type.rstrip(".").split("."):
        encoded = part.encode("utf-8")
        labels += bytes([len(encoded)]) + encoded
    labels += b"\x00"
    
    # QTYPE=PTR (12), QCLASS=IN (1) with unicast-response bit
    question = labels + struct.pack(">HH", 12, 0x8001)
    
    return header + question


def _parse_mdns_response(data: bytes) -> dict:
    """Prosta analiza odpowiedzi mDNS — wyciąga nazwę hosta."""
    result = {}
    try:
        # Skip header (12 bytes)
        offset = 12
        if len(data) < 12:
            return result
        
        answer_count = struct.unpack(">H", data[4:6])[0]
        question_count = struct.unpack(">H", data[2:4])[0]
        
        # Skip questions
        for _ in range(question_count):
            while offset < len(data) and data[offset] != 0:
                if data[offset] & 0xC0 == 0xC0:  # pointer
                    offset += 2
                    break
                offset += data[offset] + 1
            else:
                offset += 1
            offset += 4  # type + class
        
        # Parse answers
        for _ in range(answer_count):
            if offset >= len(data):
                break
            
            # Read name
            name_parts = []
            temp_offset = offset
            while temp_offset < len(data) and data[temp_offset] != 0:
                if data[temp_offset] & 0xC0 == 0xC0:
                    ptr = struct.unpack(">H", data[temp_offset:temp_offset+2])[0] & 0x3FFF
                    temp_offset += 2
                    # Follow pointer once
                    p = ptr
                    while p < len(data) and data[p] != 0:
                        if data[p] & 0xC0 == 0xC0:
                            break
                        l = data[p]
                        name_parts.append(data[p+1:p+1+l].decode("utf-8", errors="replace"))
                        p += l + 1
                    break
                else:
                    l = data[temp_offset]
                    name_parts.append(data[temp_offset+1:temp_offset+1+l].decode("utf-8", errors="replace"))
                    temp_offset += l + 1
            
            if name_parts:
                result["hostname"] = ".".join(name_parts)
                break
                
    except Exception:
        pass
    return result


def scan_mdns(timeout: float = 3.0) -> List[Dict]:
    """
    Skanuje sieć lokalną przez mDNS/Bonjour.
    Wysyła zapytania o popularne typy serwisów i zbiera odpowiedzi.
    """
    devices = {}
    
    MDNS_ADDR = "224.0.0.251"
    MDNS_PORT = 5353
    
    # Tworzymy socket multicast
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if platform.system() != "Windows":
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except AttributeError:
                pass
        sock.settimeout(timeout)
        
        # Dołącz do grupy multicast
        mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        
        # Bind
        try:
            sock.bind(("", MDNS_PORT))
        except OSError:
            sock.bind(("", 0))
        
        # Wyślij zapytania o różne typy serwisów
        services_to_query = list(MDNS_SERVICES.keys())[:12]  # top 12
        for service_type in services_to_query:
            try:
                query = _build_mdns_query(service_type)
                sock.sendto(query, (MDNS_ADDR, MDNS_PORT))
            except Exception:
                pass
        
        # Zbieraj odpowiedzi
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                
                if ip in devices:
                    continue
                if ip == "127.0.0.1":
                    continue
                    
                parsed = _parse_mdns_response(data)
                hostname = parsed.get("hostname", "")
                
                # Wykryj typ na podstawie hostname
                device_info = _classify_by_hostname(hostname)
                
                devices[ip] = {
                    "ip": ip,
                    "hostname": hostname,
                    "mac": "",
                    "status": "online",
                    "open_ports": [],
                    "discovery_method": "mDNS",
                    **device_info,
                }
                
            except socket.timeout:
                break
            except Exception:
                continue
                
    except Exception as e:
        print(f"  ⚠️ mDNS: {e}")
    finally:
        try:
            sock.close()
        except Exception:
            pass
    
    result = list(devices.values())
    if result:
        print(f"  📡 mDNS: znaleziono {len(result)} urządzeń Bonjour")
    else:
        print("  📡 mDNS: brak odpowiedzi (urządzenia Apple/Smart Home mogą być offline)")
    
    return result


def _classify_by_hostname(hostname: str) -> dict:
    """Klasyfikuje urządzenie na podstawie nazwy mDNS."""
    hn = hostname.lower()
    
    if any(x in hn for x in ["apple-tv", "appletv"]):
        return {"name": "Apple TV", "emoji": "📺", "type": "apple_tv", "category": "media",
                "label": "🏟️ Koloseum Apple", "kingdom": "Koloseum Apple", "actions": ["ping", "http_get"]}
    if any(x in hn for x in ["iphone", "ipad"]):
        return {"name": "iPhone/iPad", "emoji": "🍎", "type": "iphone", "category": "mobile",
                "label": "🍎 Twierdza Apple", "kingdom": "Twierdza Apple", "actions": ["ping"]}
    if any(x in hn for x in ["echo", "alexa", "amazon"]):
        return {"name": "Amazon Echo", "emoji": "🔊", "type": "echo", "category": "smart_home",
                "label": "🔊 Wieża Alexy", "kingdom": "Wieża Alexy", "actions": ["ping"]}
    if "chromecast" in hn:
        return {"name": "Chromecast", "emoji": "📡", "type": "chromecast", "category": "media",
                "label": "📡 Wieża Google", "kingdom": "Wieża Google", "actions": ["ping", "http_get"]}
    if any(x in hn for x in ["hue", "philips"]):
        return {"name": "Philips Hue", "emoji": "💡", "type": "philips_hue", "category": "smart_home",
                "label": "💡 Latarnia Hue", "kingdom": "Latarnia Hue", "actions": ["ping", "http_get", "get_lights"]}
    if "homeassistant" in hn or "hassio" in hn:
        return {"name": "Home Assistant", "emoji": "🏡", "type": "home_assistant", "category": "smart_home",
                "label": "🏡 Zamek HA", "kingdom": "Zamek HA", "actions": ["ping", "http_get"]}
    if "raspberrypi" in hn or "raspberry" in hn:
        return {"name": "Raspberry Pi", "emoji": "🥧", "type": "raspberry_pi", "category": "server",
                "label": "🥧 Bastion Pi", "kingdom": "Bastion Pi", "actions": ["ping", "ssh_connect"]}
    if any(x in hn for x in ["synology", "diskstation", "qnap", "nas"]):
        return {"name": "NAS", "emoji": "💾", "type": "nas", "category": "storage",
                "label": "💾 Skarbiec NAS", "kingdom": "Skarbiec NAS", "actions": ["ping", "http_get"]}
    if any(x in hn for x in ["printer", "hp", "epson", "canon", "brother"]):
        return {"name": "Drukarka", "emoji": "🖨️", "type": "printer", "category": "peripheral",
                "label": "🖨️ Skryptorium", "kingdom": "Skryptorium", "actions": ["ping", "http_get"]}
    
    return {"name": hostname or "Bonjour Device", "emoji": "📡", "type": "bonjour_device", "category": "network",
            "label": "📡 Wysłannik Bonjour", "kingdom": "Wysłannik Bonjour", "actions": ["ping"]}
