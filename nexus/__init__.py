"""Mycelium Nexus — self-expanding device detection and module generation."""
import json, os, time, threading, importlib.util
from typing import Dict, Any, List, Callable, Optional
from collections import deque

# ── DataBus ────────────────────────────────────────────────────────────────
class DataBus:
    def __init__(self):
        self._data: Dict[str, deque] = {}
        self._lock = threading.Lock()
    def publish(self, device_id: str, values: dict):
        e = {'ts': time.time(), 'values': values}
        with self._lock:
            if device_id not in self._data:
                self._data[device_id] = deque(maxlen=500)
            self._data[device_id].append(e)
    def get_latest(self, device_id: str) -> dict:
        with self._lock:
            d = self._data.get(device_id)
            return d[-1] if d else {}
    def get_history(self, device_id: str, n=100) -> list:
        with self._lock:
            return list(self._data.get(device_id, []))[-n:]
    def list_devices(self): 
        with self._lock: return list(self._data.keys())

# ── ModuleRegistry ─────────────────────────────────────────────────────────
_NEXUS_DIR = os.path.dirname(__file__)
_GEN_DIR = os.path.join(_NEXUS_DIR, 'modules', '_generated')
_REG_PATH = os.path.join(_NEXUS_DIR, 'modules', 'registry.json')

class ModuleRegistry:
    def __init__(self):
        self._mods: Dict[str, Any] = {}
        self._lock = threading.Lock()
        os.makedirs(_GEN_DIR, exist_ok=True)
        self._load_all()
    def _load_all(self):
        for name in ['hackrf','rtlsdr','arduino','gps']:
            p = os.path.join(_NEXUS_DIR, 'modules', f'{name}.py')
            if os.path.exists(p): self._load_file(name, p)
        if os.path.exists(_REG_PATH):
            try:
                with open(_REG_PATH) as f: reg = json.load(f)
                for n, p in reg.items():
                    if os.path.exists(p): self._load_file(n, p)
            except: pass
    def _load_file(self, name, path):
        try:
            spec = importlib.util.spec_from_file_location(f'nxm_{name}', path)
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            self._mods[name] = m
        except: pass
    def get_module(self, name) -> Optional[Any]:
        with self._lock: return self._mods.get(name)
    def save_generated(self, name: str, code: str) -> str:
        path = os.path.join(_GEN_DIR, f'{name}.py')
        with open(path, 'w') as f: f.write(code)
        self._load_file(name, path)
        reg = {}
        if os.path.exists(_REG_PATH):
            try:
                with open(_REG_PATH) as f: reg = json.load(f)
            except: pass
        reg[name] = path
        with open(_REG_PATH, 'w') as f: json.dump(reg, f, indent=2)
        return path
    def list_modules(self):
        with self._lock: return list(self._mods.keys())

# ── AI Generator ───────────────────────────────────────────────────────────
def generate_module_ai(device_info: dict, api_key: str) -> Optional[str]:
    import urllib.request
    prompt = f"""Generate a Python Mycelium Nexus device module for:
Name: {device_info.get('name')}, VID:{device_info.get('vid')}, PID:{device_info.get('pid')}
Class: {device_info.get('device_class')}, Caps: {device_info.get('capabilities')}
Port: {device_info.get('port','None')}

Required interface:
DEVICE_INFO = dict(name,device_class,capabilities,icon,description,vid,pid)
def init(config=None)->bool
def collect()->dict  (return zeroed data if device not connected)
def stop()
def get_schema()->dict  (channels:[{{name,unit,min,max,color}}],refresh_ms,visualization)
def get_latest()->dict
Return ONLY valid Python, no markdown."""
    try:
        payload = json.dumps({"model":"gpt-4o-mini","messages":[
            {"role":"system","content":"Python hardware driver expert. Return only valid Python."},
            {"role":"user","content":prompt}],"max_tokens":2000,"temperature":0.2}).encode()
        req = urllib.request.Request('https://api.openai.com/v1/chat/completions',
            data=payload, headers={'Authorization':f'Bearer {api_key}','Content-Type':'application/json'})
        with urllib.request.urlopen(req, timeout=30) as r:
            code = json.loads(r.read())['choices'][0]['message']['content']
            for m in ['```python','```']:
                if code.startswith(m): code = code[len(m):]
            if code.endswith('```'): code = code[:-3]
            return code.strip()
    except: return None

def generate_module_template(device_info: dict) -> str:
    caps = device_info.get('capabilities',['data'])
    name = device_info.get('name','Unknown')
    channels = [{"name":c,"unit":"","min":0,"max":100,"color":"#00ff88"} for c in caps[:4]]
    ret = '{' + ', '.join(f'"{c}":0.0' for c in caps[:4]) + '}'
    return f'''"""Auto-generated module for {name}"""
import time, threading
DEVICE_INFO={{"name":"{name}","device_class":"{device_info.get('device_class','unknown')}","capabilities":{json.dumps(caps)},"icon":"{device_info.get('icon','🔌')}","description":"Auto-generated","vid":"{device_info.get('vid','0000')}","pid":"{device_info.get('pid','0000')}"}}
_latest={{}}; _running=False
def init(config=None):
    global _running; _running=True
    threading.Thread(target=_loop,daemon=True).start(); return True
def _loop():
    while _running: _latest.update(collect()); time.sleep(1)
def collect(): return {ret}
def stop():
    global _running; _running=False
def get_schema(): return {{"channels":{json.dumps(channels)},"refresh_ms":1000,"visualization":"line_chart"}}
def get_latest(): return dict(_latest)
'''

from .detector import DeviceDetector
from .fingerprint import identify as fingerprint_identify
__all__ = ['DeviceDetector','ModuleRegistry','DataBus','generate_module_ai','generate_module_template','fingerprint_identify']

