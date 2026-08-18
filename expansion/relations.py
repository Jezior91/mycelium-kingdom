"""
🍄 MYCELIUM — Kingdom Relations (Mapa Relacji)
Śledzi zależności i relacje między królestwami:
- Kto jest bramą (gateway)?
- Które królestwa ze sobą rozmawiają?
- Topologia sieci — kto jest centrum, kto jest peryferiami?
"""

import socket
import subprocess
import platform
import re
from typing import Dict, List, Tuple, Optional


def traceroute_to(target_ip: str, max_hops: int = 10, timeout: int = 3) -> List[dict]:
    """Mapuje trasę do królestwa — lista pośrednich węzłów."""
    hops = []
    
    is_win = platform.system() == "Windows"
    
    if is_win:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout * 1000), target_ip]
    else:
        cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout), target_ip]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        lines = result.stdout.split("\n")
        
        hop_num = 0
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # Extract hop number and IP
            if is_win:
                m = re.match(r"\s*(\d+)\s+.*?(\d+\.\d+\.\d+\.\d+)", line)
            else:
                m = re.match(r"\s*(\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
            
            if m:
                hop_num = int(m.group(1))
                hop_ip = m.group(2)
                hops.append({
                    "hop": hop_num,
                    "ip": hop_ip,
                    "latency_ms": _extract_latency(line),
                })
            elif "*" in line and re.match(r"\s*(\d+)\s+\*", line):
                hop_num += 1
                hops.append({"hop": hop_num, "ip": "*", "latency_ms": None})
    
    except Exception as e:
        pass
    
    return hops


def _extract_latency(line: str) -> Optional[float]:
    """Wyciąga czas odpowiedzi z linii traceroute."""
    m = re.search(r"(\d+\.?\d*)\s*ms", line)
    return float(m.group(1)) if m else None


def build_network_graph(devices: List[dict], gateway_ip: str = None) -> dict:
    """
    Buduje graf relacji między królestwami.
    Zwraca węzły i krawędzie dla wizualizacji.
    """
    nodes = []
    edges = []
    
    # Dodaj węzły
    for d in devices:
        ip = d.get("ip", "")
        dtype = d.get("type", "unknown")
        
        # Centryczność — routery i serwery są bardziej centralne
        centrality = {
            "router": 1.0,
            "linux_server": 0.8,
            "windows_pc": 0.6,
            "nas": 0.7,
            "raspberry_pi": 0.6,
            "smart_tv": 0.4,
            "android_phone": 0.3,
            "iphone": 0.3,
            "printer": 0.2,
            "powerline": 0.5,
        }.get(dtype, 0.4)
        
        is_gateway = (ip == gateway_ip) or dtype == "router"
        
        nodes.append({
            "id": ip,
            "label": d.get("kingdom", d.get("name", ip)),
            "emoji": d.get("emoji", "❓"),
            "type": dtype,
            "ip": ip,
            "status": d.get("status", "unknown"),
            "centrality": centrality,
            "is_gateway": is_gateway,
            "open_ports": d.get("open_ports", []),
        })
    
    # Dodaj krawędzie — wszystko przez gateway
    if gateway_ip:
        for d in devices:
            ip = d.get("ip", "")
            if ip and ip != gateway_ip:
                edges.append({
                    "source": ip,
                    "target": gateway_ip,
                    "type": "routed",
                    "label": "→ brama",
                })
    
    # Wykryj bezpośrednie relacje (shared services)
    for i, d1 in enumerate(devices):
        for d2 in devices[i+1:]:
            relation = _detect_relation(d1, d2)
            if relation:
                edges.append({
                    "source": d1.get("ip"),
                    "target": d2.get("ip"),
                    "type": relation["type"],
                    "label": relation["label"],
                })
    
    return {
        "nodes": nodes,
        "edges": edges,
        "gateway": gateway_ip,
        "total_kingdoms": len(nodes),
        "total_relations": len(edges),
    }


def _detect_relation(d1: dict, d2: dict) -> Optional[dict]:
    """Wykrywa potencjalną relację między dwoma urządzeniami."""
    t1 = d1.get("type", "")
    t2 = d2.get("type", "")
    p1 = set(d1.get("open_ports", []))
    p2 = set(d2.get("open_ports", []))
    
    # Drukarka ↔ komputer
    if "printer" in (t1, t2) and any(x in (t1, t2) for x in ("windows_pc", "linux_server", "mac_pc")):
        return {"type": "print", "label": "🖨️ drukuje"}
    
    # NAS ↔ komputer (SMB)
    if "nas" in (t1, t2) and (445 in p1 or 445 in p2):
        other_type = t2 if t1 == "nas" else t1
        if other_type in ("windows_pc", "linux_server", "mac_pc"):
            return {"type": "storage", "label": "💾 przechowuje"}
    
    # Hue Bridge ↔ cokolwiek z HTTP
    if "philips_hue" in (t1, t2):
        return {"type": "iot", "label": "💡 steruje"}
    
    # Home Assistant ↔ IoT
    if "home_assistant" in (t1, t2):
        other_type = t2 if t1 == "home_assistant" else t1
        if other_type in ("shelly", "mqtt_broker", "philips_hue", "esp_device"):
            return {"type": "automation", "label": "🏡 automatyzuje"}
    
    # MQTT ↔ IoT devices
    if "mqtt_broker" in (t1, t2) and 1883 in (p1 | p2):
        return {"type": "messaging", "label": "📨 MQTT"}
    
    # Powerline ↔ cokolwiek
    if "powerline" in (t1, t2):
        return {"type": "powerline", "label": "⚡ prąd"}
    
    return None


def find_gateway(devices: List[dict]) -> Optional[str]:
    """Próbuje zidentyfikować bramę sieciową (router)."""
    # Najpierw szukaj po typie
    for d in devices:
        if d.get("type") == "router":
            return d.get("ip")
    
    # Potem przez system
    try:
        if platform.system() == "Windows":
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            m = re.search(r"Default Gateway.*?:\s*(\d+\.\d+\.\d+\.\d+)", result.stdout)
        else:
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", result.stdout)
        
        if m:
            return m.group(1)
    except Exception:
        pass
    
    return None


def measure_latency(ips: List[str], count: int = 3) -> Dict[str, float]:
    """Mierzy latencję do każdego królestwa."""
    results = {}
    is_win = platform.system() == "Windows"
    
    for ip in ips:
        try:
            if is_win:
                cmd = ["ping", "-n", str(count), "-w", "1000", ip]
            else:
                cmd = ["ping", "-c", str(count), "-W", "1", ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            # Extract average latency
            if is_win:
                m = re.search(r"Average = (\d+)ms", result.stdout)
            else:
                m = re.search(r"avg.*?= [\d.]+/([\d.]+)", result.stdout)
            
            if m:
                results[ip] = float(m.group(1))
            else:
                results[ip] = -1.0  # timeout
        except Exception:
            results[ip] = -1.0
    
    return results
