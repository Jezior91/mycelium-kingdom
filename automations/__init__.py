"""
Automation Engine — triggers + actions
Persists to data/automations.json
"""
import json, time, threading, os, subprocess
from datetime import datetime

_BASE = os.path.dirname(__file__)
AUTOMATIONS_FILE = os.path.join(_BASE, '..', 'data', 'automations.json')

def load_automations():
    try:
        with open(AUTOMATIONS_FILE) as f:
            return json.load(f)
    except Exception:
        return []

def save_automations(automations):
    os.makedirs(os.path.dirname(os.path.abspath(AUTOMATIONS_FILE)), exist_ok=True)
    with open(AUTOMATIONS_FILE, 'w') as f:
        json.dump(automations, f, indent=2)

def execute_action(action: dict):
    kind = action.get('type')
    try:
        if kind == 'http':
            import urllib.request
            req = urllib.request.Request(action['url'], method=action.get('method','GET'))
            urllib.request.urlopen(req, timeout=10)
        elif kind == 'script':
            subprocess.Popen(action['command'], shell=True)
        elif kind == 'log':
            print(f"[AUTO] {action.get('message','')}")
    except Exception as e:
        print(f"[AUTO] action error: {e}")

class AutomationEngine:
    def __init__(self):
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            self._tick()
            time.sleep(10)

    def _tick(self):
        now = datetime.now()
        automations = load_automations()
        changed = False
        for a in automations:
            if not a.get('enabled', True):
                continue
            trigger = a.get('trigger', {})
            ttype = trigger.get('type')
            if ttype == 'interval':
                interval = int(trigger.get('seconds', 60))
                last = a.get('last_run', 0)
                if time.time() - last >= interval:
                    for act in a.get('actions', []):
                        execute_action(act)
                    a['last_run'] = time.time()
                    changed = True
            elif ttype == 'time':
                target = trigger.get('time', '00:00')
                if now.strftime('%H:%M') == target:
                    last_date = a.get('last_run_date', '')
                    today = now.strftime('%Y-%m-%d')
                    if last_date != today:
                        for act in a.get('actions', []):
                            execute_action(act)
                        a['last_run_date'] = today
                        changed = True
        if changed:
            save_automations(automations)

    def add(self, automation: dict) -> dict:
        automations = load_automations()
        automation['id'] = str(int(time.time() * 1000))
        automation['created'] = datetime.now().isoformat()
        automation.setdefault('enabled', True)
        automations.append(automation)
        save_automations(automations)
        return automation

    def delete(self, aid: str):
        automations = [a for a in load_automations() if a.get('id') != aid]
        save_automations(automations)

    def toggle(self, aid: str):
        automations = load_automations()
        for a in automations:
            if a.get('id') == aid:
                a['enabled'] = not a.get('enabled', True)
        save_automations(automations)
        return next((a for a in automations if a['id'] == aid), None)

engine = AutomationEngine()
