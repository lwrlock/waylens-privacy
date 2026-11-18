from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA_DIR = pathlib.Path.home() / ".local/share/waylens-privacy"
TRUST_FILE = DATA_DIR / "trusted_usb.json"
AUDIT_FILE = DATA_DIR / "audit.jsonl"


def probe_environment() -> dict:
    probe = ROOT / "waylens-probe"
    out = subprocess.check_output([str(probe), "--json"], text=True, timeout=3.0)
    data = json.loads(out)
    data["ssh_keys_loaded"] = count_ssh_keys()
    trusted = load_trusted_usb()
    data["trusted_usb"] = trusted
    data["unknown_usb"] = detect_untrusted_usb(data.get("usb_devices", []), trusted)
    return data


def count_ssh_keys() -> int:
    try:
        res = subprocess.run(["/usr/bin/ssh-add", "-l"], capture_output=True, text=True, timeout=1.0)
        if res.returncode == 0:
            return len([ln for ln in res.stdout.splitlines() if ln.strip()])
    except Exception:
        pass
    return 0


def lock_ssh_agent() -> bool:
    """Drop decrypted SSH agent identities safely without modifying keys on disk."""
    try:
        return subprocess.run(["/usr/bin/ssh-add", "-D"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.0).returncode == 0
    except Exception:
        return False


def clear_clipboard() -> None:
    for cmd in (["/usr/bin/wl-copy", "--clear"], ["/usr/bin/xclip", "-selection", "clipboard", "-i", "/dev/null"]):
        try:
            if pathlib.Path(cmd[0]).exists():
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.8)
                return
        except Exception:
            pass


def load_trusted_usb(path: pathlib.Path = TRUST_FILE) -> set[str]:
    try:
        if path.exists():
            return set(json.loads(path.read_text()))
    except Exception:
        pass
    return set()


def save_trusted_usb(devices: list[dict], path: pathlib.Path = TRUST_FILE) -> set[str]:
    keys = sorted({f"{d.get('port', '')}:{d.get('id', '')}" for d in devices if d.get("id")})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(keys, indent=2) + "\n")
    os.chmod(path, 0o600)
    return set(keys)


def detect_untrusted_usb(devices: list[dict], trusted_keys: set[str]) -> list[dict]:
    if not trusted_keys:
        return []
    alerts = []
    for d in devices:
        k = f"{d.get('port', '')}:{d.get('id', '')}"
        if k not in trusted_keys:
            alerts.append(d)
    return alerts


def evaluate_vault_state(tof_state: str, distance_cm: int, unknown_usb: list[dict]) -> tuple[str, str]:
    if any(u.get("hid_or_storage") for u in unknown_usb):
        return "USB_INTRUSION_LOCK", f"Untrusted USB HID/Storage ({unknown_usb[0].get('product', 'Device')})"
    if unknown_usb:
        return "USB_ALERT", f"New USB device ({unknown_usb[0].get('id', '?')})"
    if tof_state == "absent":
        return "AWAY_VAULT_LOCKED", "Operator absent — SSH & screen vault armed"
    if tof_state == "present" and 0 < distance_cm <= 25:
        return "PROXIMITY_CLOSE", f"Close operator range ({distance_cm} cm)"
    if tof_state == "present":
        return "ARMED_AT_DESK", f"Verified operator at {distance_cm} cm"
    return "PASSIVE_GUARD", "ToF radar standby — USB guard active"


def append_audit_event(event_type: str, detail: str, audit_path: pathlib.Path = AUDIT_FILE) -> str:
    """Append hash-chained tamper-evident JSONL security audit record."""
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    prev_hash = "0" * 64
    if audit_path.exists():
        try:
            lines = [ln for ln in audit_path.read_text().splitlines() if ln.strip()]
            if lines:
                prev_hash = json.loads(lines[-1]).get("hash", prev_hash)
        except Exception:
            pass
    payload = {"ts": int(time.time()), "event": event_type, "detail": detail, "prev": prev_hash}
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    payload["hash"] = digest
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")
    os.chmod(audit_path, 0o600)
    return digest
