"""Fast async port scanner"""
import asyncio
import socket
from typing import List, Dict

COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 554: 'RTSP', 1883: 'MQTT',
    3306: 'MySQL', 3389: 'RDP', 5000: 'Flask', 5900: 'VNC',
    6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    8883: 'MQTT-TLS', 9200: 'Elasticsearch', 27017: 'MongoDB'
}

async def _check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def scan_host_async(ip: str, ports: List[int] = None, timeout: float = 0.5) -> Dict:
    if ports is None:
        ports = list(COMMON_PORTS.keys())
    tasks = [_check_port(ip, p, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = []
    for port, is_open in zip(ports, results):
        if is_open:
            open_ports.append({'port': port, 'service': COMMON_PORTS.get(port, 'unknown')})
    return {'ip': ip, 'open_ports': open_ports}

def scan_host(ip: str, ports: List[int] = None) -> Dict:
    """Synchronous wrapper — runs in new event loop"""
    try:
        loop = asyncio.new_event_loop()
        return loop.run_until_complete(scan_host_async(ip, ports))
    except Exception as e:
        return {'ip': ip, 'open_ports': [], 'error': str(e)}
    finally:
        loop.close()
