"""Nexus Device Detector — Windows USB/COM/PnP device detection."""
import subprocess, threading, time, re
from typing import Callable, Dict, List, Optional
from dataclasses import dataclass, field, asdict

@dataclass
class DetectedDevice:
    device_id: str
    name: str
    vid: Optional[str]
    pid: Optional[str]
    port: Optional[str]
    device_type: str
    raw_info: dict = field(default_factory=dict)
    def to_dict(self): return asdict(self)

class DeviceDetector:
    def __init__(self):
        self._known: Dict[str, DetectedDevice] = {}
        self._callbacks_connect: List[Callable] = []
        self._callbacks_disconnect: List[Callable] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def on_connect(self, cb): self._callbacks_connect.append(cb)
    def on_disconnect(self, cb): self._callbacks_disconnect.append(cb)

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self): self._running = False

    def get_current_devices(self) -> List[DetectedDevice]:
        with self._lock:
            return list(self._known.values())

    def scan_once(self) -> List[DetectedDevice]:
        """Trigger an immediate scan and return results."""
        current = self._scan_all()
        current_ids = {d.device_id for d in current}
        with self._lock:
            known_ids = set(self._known.keys())
            for d in current:
                if d.device_id not in known_ids:
                    self._known[d.device_id] = d
                    for cb in self._callbacks_connect:
                        try: cb(d)
                        except: pass
            for did in known_ids - current_ids:
                dev = self._known.pop(did)
                for cb in self._callbacks_disconnect:
                    try: cb(dev)
                    except: pass
        return list(self._known.values())

    def _loop(self):
        while self._running:
            try: self.scan_once()
            except: pass
            time.sleep(5)

    def _scan_all(self) -> List[DetectedDevice]:
        devices = []
        devices.extend(self._scan_usb_pnp())
        devices.extend(self._scan_serial_ports())
        return devices

    def _scan_usb_pnp(self) -> List[DetectedDevice]:
        devices = []
        try:
            flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            result = subprocess.run(
                ['wmic','path','Win32_PnPEntity','get','DeviceID,Name,Status','/format:csv'],
                capture_output=True, text=True, timeout=10, creationflags=flags)
            for line in result.stdout.splitlines():
                if 'VID_' not in line.upper(): continue
                parts = line.strip().split(',')
                if len(parts) < 3: continue
                device_id, name = parts[1], parts[2]
                if not device_id or not name: continue
                vm = re.search(r'VID_([0-9A-Fa-f]{4})', device_id)
                pm = re.search(r'PID_([0-9A-Fa-f]{4})', device_id)
                vid = vm.group(1).upper() if vm else None
                pid = pm.group(1).upper() if pm else None
                dev_id = f"usb_{vid}_{pid}" if vid and pid else f"usb_{device_id[:32]}"
                devices.append(DetectedDevice(dev_id, name.strip(), vid, pid, None, 'usb', {'device_id': device_id}))
        except: pass
        return devices

    def _scan_serial_ports(self) -> List[DetectedDevice]:
        devices = []
        try:
            import serial.tools.list_ports
            for port in serial.tools.list_ports.comports():
                vid = f"{port.vid:04X}" if port.vid else None
                pid = f"{port.pid:04X}" if port.pid else None
                devices.append(DetectedDevice(
                    f"serial_{port.device}", port.description or port.device,
                    vid, pid, port.device, 'serial', {'hwid': port.hwid or ''}))
        except ImportError:
            try:
                flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                result = subprocess.run(
                    ['wmic','path','Win32_SerialPort','get','DeviceID,Name','/format:csv'],
                    capture_output=True, text=True, timeout=5, creationflags=flags)
                for line in result.stdout.splitlines():
                    parts = line.strip().split(',')
                    if len(parts) >= 3 and parts[2]:
                        devices.append(DetectedDevice(f"serial_{parts[1]}", parts[2].strip(), None, None, parts[1], 'serial', {}))
            except: pass
        except: pass
        return devices
