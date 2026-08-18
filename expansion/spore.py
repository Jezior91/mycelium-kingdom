"""
🍄 MYCELIUM — Spore Deployment (Zarodniki)
Instaluje lekki węzeł Mycelium na urządzeniach SSH/Linux.
Węzeł odsyła dane z wnętrza urządzenia — CPU, RAM, procesy, sieć.

WAŻNE: Działa TYLKO na urządzeniach autoryzowanych (Twoje własne).
Wymaga podania hasła SSH lub klucza.
"""

import socket
import json
import time
import threading
from datetime import datetime
from typing import Dict, List, Optional


# Mini-agent do wdrożenia na docelowe urządzenie
SPORE_SCRIPT = '''#!/usr/bin/env python3
"""🍄 Mycelium Spore Node — lekki węzeł raportujący"""
import json, time, socket, subprocess, platform, os

def collect():
    data = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "timestamp": time.time(),
        "cpu_count": os.cpu_count(),
    }
    
    # CPU usage
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        cols = list(map(int, line.split()[1:]))
        idle = cols[3]
        total = sum(cols)
        data["cpu_idle_pct"] = round(idle / total * 100, 1)
    except:
        data["cpu_idle_pct"] = -1
    
    # RAM
    try:
        with open("/proc/meminfo") as f:
            lines = f.readlines()
        mem = {}
        for line in lines[:5]:
            k, v = line.split(":")
            mem[k.strip()] = int(v.split()[0])
        data["ram_total_mb"] = mem.get("MemTotal", 0) // 1024
        data["ram_free_mb"] = mem.get("MemFree", 0) // 1024
        data["ram_avail_mb"] = mem.get("MemAvailable", 0) // 1024
    except:
        pass
    
    # Disk
    try:
        r = subprocess.run(["df", "-h", "/"], capture_output=True, text=True)
        lines = r.stdout.strip().split("\\n")
        if len(lines) > 1:
            parts = lines[1].split()
            data["disk_total"] = parts[1]
            data["disk_used"] = parts[2]
            data["disk_free"] = parts[3]
            data["disk_pct"] = parts[4]
    except:
        pass
    
    # Top processes
    try:
        r = subprocess.run(["ps", "aux", "--sort=-%cpu"], capture_output=True, text=True)
        lines = r.stdout.strip().split("\\n")[1:6]
        procs = []
        for line in lines:
            parts = line.split(None, 10)
            if len(parts) >= 11:
                procs.append({"user": parts[0], "cpu": parts[2], "mem": parts[3], "cmd": parts[10][:60]})
        data["top_processes"] = procs
    except:
        data["top_processes"] = []
    
    # Open ports
    try:
        r = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True)
        ports = []
        for line in r.stdout.split("\\n")[1:]:
            parts = line.split()
            if len(parts) >= 4:
                addr = parts[3]
                port = addr.split(":")[-1]
                try:
                    ports.append(int(port))
                except:
                    pass
        data["listening_ports"] = list(set(ports))
    except:
        data["listening_ports"] = []
    
    # Network interfaces
    try:
        r = subprocess.run(["ip", "-j", "addr"], capture_output=True, text=True)
        ifaces = json.loads(r.stdout)
        data["interfaces"] = [
            {"name": i["ifname"], "addrs": [a["local"] for a in i.get("addr_info", [])]}
            for i in ifaces if i.get("operstate") == "UP"
        ]
    except:
        data["interfaces"] = []
    
    return data

if __name__ == "__main__":
    report = collect()
    print("MYCELIUM_SPORE_DATA:" + json.dumps(report))
'''


class SporeDeployer:
    """Wdraża i odpytuje węzły Mycelium na autoryzowanych urządzeniach."""
    
    def __init__(self, agent):
        self.agent = agent
        self.active_nodes: Dict[str, dict] = {}
        self.deployment_log: List[dict] = []
    
    def deploy(self, ip: str, username: str, password: str = None,
               key_path: str = None) -> dict:
        """
        Wdraża zarodnik na urządzenie SSH.
        Wymaga: IP + username + (hasło LUB ścieżka do klucza SSH).
        """
        self._log(f"🌱 Wdrażam zarodnik na {ip} jako {username}...")
        
        # Sprawdź czy paramiko jest dostępne
        try:
            import paramiko
        except ImportError:
            return {
                "success": False,
                "error": "Brak biblioteki paramiko. Zainstaluj: pip install paramiko",
                "ip": ip,
            }
        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {
                "hostname": ip,
                "username": username,
                "timeout": 10,
                "banner_timeout": 10,
            }
            
            if key_path:
                connect_kwargs["key_filename"] = key_path
            elif password:
                connect_kwargs["password"] = password
            else:
                return {"success": False, "error": "Podaj hasło lub ścieżkę do klucza SSH", "ip": ip}
            
            client.connect(**connect_kwargs)
            
            # Wyślij skrypt
            sftp = client.open_sftp()
            import io
            script_bytes = SPORE_SCRIPT.encode("utf-8")
            sftp.putfo(io.BytesIO(script_bytes), "/tmp/mycelium_spore.py")
            sftp.close()
            
            # Uruchom i zbierz dane
            stdin, stdout, stderr = client.exec_command(
                "python3 /tmp/mycelium_spore.py 2>/dev/null"
            )
            output = stdout.read().decode("utf-8", errors="replace")
            
            client.close()
            
            # Parsuj wyniki
            node_data = self._parse_spore_output(output, ip)
            
            if node_data:
                self.active_nodes[ip] = {
                    **node_data,
                    "ip": ip,
                    "username": username,
                    "last_seen": datetime.now().isoformat(),
                    "deployment_time": datetime.now().isoformat(),
                }
                
                # Zaktualizuj urządzenie w agencie
                if ip in self.agent.devices:
                    self.agent.devices[ip].update({
                        "spore_active": True,
                        "spore_data": node_data,
                        "hostname": node_data.get("hostname", self.agent.devices[ip].get("hostname", "")),
                    })
                    self.agent._save_devices()
                
                self._log(f"✅ Zarodnik aktywny na {ip} — {node_data.get('hostname', ip)}")
                return {"success": True, "ip": ip, "data": node_data}
            else:
                return {"success": False, "error": "Nie można sparsować danych ze zarodnika", "ip": ip}
                
        except Exception as e:
            self._log(f"❌ Błąd wdrożenia na {ip}: {e}")
            return {"success": False, "error": str(e), "ip": ip}
    
    def collect(self, ip: str, username: str, password: str = None, key_path: str = None) -> Optional[dict]:
        """Zbiera dane z istniejącego zarodnika (re-uruchomienie skryptu)."""
        return self.deploy(ip, username, password, key_path)
    
    def _parse_spore_output(self, output: str, ip: str) -> Optional[dict]:
        """Parsuje output zarodnika."""
        for line in output.split("\n"):
            if line.startswith("MYCELIUM_SPORE_DATA:"):
                try:
                    json_str = line[len("MYCELIUM_SPORE_DATA:"):]
                    return json.loads(json_str)
                except Exception:
                    pass
        return None
    
    def get_node_status(self, ip: str) -> Optional[dict]:
        """Zwraca ostatnio znane dane węzła."""
        return self.active_nodes.get(ip)
    
    def get_all_nodes(self) -> List[dict]:
        return list(self.active_nodes.values())
    
    def _log(self, msg: str):
        entry = {"time": datetime.now().strftime("%H:%M:%S"), "msg": msg}
        self.deployment_log.append(entry)
        if len(self.deployment_log) > 100:
            self.deployment_log = self.deployment_log[-100:]
        print(f"[Spore] {entry['time']} — {msg}")


# ─── PASYWNY LISTENER ────────────────────────────────────────────────────────

class SporeListener:
    """
    Nasłuchuje na port TCP, żeby węzły same mogły się raportować.
    Węzły mogą wysyłać dane automatycznie co N minut.
    """
    
    def __init__(self, port: int = 47474):
        self.port = port
        self.received: List[dict] = []
        self._running = False
        self._thread = None
    
    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._listen, daemon=True)
        self._thread.start()
        print(f"🍄 SporeListener nasłuchuje na :{self.port}")
    
    def stop(self):
        self._running = False
    
    def _listen(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("0.0.0.0", self.port))
            server.listen(10)
            server.settimeout(1.0)
            
            while self._running:
                try:
                    conn, addr = server.accept()
                    data = b""
                    conn.settimeout(3.0)
                    while True:
                        chunk = conn.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                    conn.close()
                    
                    if data:
                        try:
                            payload = json.loads(data.decode("utf-8"))
                            payload["_from_ip"] = addr[0]
                            payload["_received_at"] = datetime.now().isoformat()
                            self.received.append(payload)
                        except Exception:
                            pass
                except socket.timeout:
                    continue
                except Exception:
                    continue
            
            server.close()
        except Exception as e:
            print(f"⚠️ SporeListener error: {e}")
    
    def get_recent(self, limit: int = 20) -> List[dict]:
        return self.received[-limit:]
