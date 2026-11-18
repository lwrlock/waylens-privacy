from __future__ import annotations

import json
import math
import os
import threading

os.environ.setdefault("GSK_RENDERER", "gl")

import cairo
import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, GLib, Gtk

from .vault import (
    AUDIT_FILE,
    append_audit_event,
    clear_clipboard,
    evaluate_vault_state,
    lock_ssh_agent,
    probe_environment,
    save_trusted_usb,
)

VAULT_CSS = b"""
window, window.background, AdwApplicationWindow {
    background-color: #08060a;
    background-image: radial-gradient(circle at 18% 12%, rgba(244, 63, 94, 0.12), transparent 46%),
                      radial-gradient(circle at 86% 85%, rgba(16, 185, 129, 0.08), transparent 46%);
    color: #fff1f2;
}
headerbar, AdwHeaderBar {
    background: #100b14;
    border-bottom: 1px solid rgba(244, 63, 94, 0.25);
    color: #fff1f2;
    min-height: 42px;
}
.threat-banner-ok {
    background: rgba(6, 36, 28, 0.90);
    border: 1px solid rgba(16, 185, 129, 0.36);
    border-radius: 10px;
    padding: 12px 16px;
}
.threat-banner-warn {
    background: rgba(45, 25, 10, 0.90);
    border: 1px solid rgba(245, 158, 11, 0.42);
    border-radius: 10px;
    padding: 12px 16px;
}
.threat-banner-alert {
    background: rgba(54, 12, 20, 0.92);
    border: 1px solid rgba(244, 63, 94, 0.55);
    border-radius: 10px;
    padding: 12px 16px;
}
.v-panel {
    background: #120d16;
    border: 1px solid rgba(244, 63, 94, 0.22);
    border-radius: 9px;
    padding: 13px 15px;
}
.banner-title { font-size: 18px; font-weight: 800; color: #f8fafc; letter-spacing: 0.4px; }
.st { font-size: 13.5px; font-weight: 700; color: #fff1f2; }
.ss { font-size: 11px; color: #94a3b8; }
.mono { font-family: monospace; font-size: 11.5px; color: #e2e8f0; }
.audit-entry {
    background: #0c080f;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 6px;
    padding: 6px 8px;
}
.usb-row {
    background: #0e0a12;
    border: 1px solid rgba(255, 255, 255, 0.07);
    border-radius: 7px;
    padding: 7px 10px;
}
.tag-ok {
    background: rgba(16, 185, 129, 0.20); color: #6ee7b7;
    border-radius: 4px; padding: 2px 7px; font-size: 10px; font-weight: 700;
}
.tag-warn {
    background: rgba(245, 158, 11, 0.22); color: #fcd34d;
    border-radius: 4px; padding: 2px 7px; font-size: 10px; font-weight: 700;
}
.tag-bad {
    background: rgba(244, 63, 94, 0.25); color: #fda4af;
    border-radius: 4px; padding: 2px 7px; font-size: 10px; font-weight: 700;
}
.act-btn {
    border-radius: 7px; padding: 6px 12px; font-size: 11.5px; font-weight: 700;
    background: rgba(244, 63, 94, 0.18); border: 1px solid rgba(251, 113, 133, 0.36);
}
.act-btn:hover { background: rgba(244, 63, 94, 0.32); }
switch:checked { background: #10b981; }
scale highlight { background: #f43f5e; }
scale slider { background: #ffe4e6; }
"""


class PolarSonarCanvas(Gtk.DrawingArea):
    """Polar ST VL53L1 ToF sonar display with degree ticks and distance range rings."""

    def __init__(self) -> None:
        super().__init__()
        self.set_size_request(-1, 225)
        self.set_hexpand(True)
        self._dist = 55
        self._thresh = 120
        self._state = "present"
        self._alert = False
        self._sweep = 0.0
        self.set_draw_func(self._draw)
        GLib.timeout_add(75, self._tick)

    def _tick(self) -> bool:
        self._sweep = (self._sweep + 0.09) % math.tau
        self.queue_draw()
        return GLib.SOURCE_CONTINUE

    def update_state(self, state: str, dist: int, thresh: int, alert: bool) -> None:
        self._state = state
        self._dist = dist
        self._thresh = max(30, thresh)
        self._alert = alert

    def _draw(self, _a, cr: cairo.Context, w: int, h: int) -> None:
        cr.set_source_rgba(0.04, 0.02, 0.05, 0.96)
        cr.rectangle(0, 0, w, h)
        cr.fill()
        cx, cy = w * 0.5, h * 0.53
        max_r = min(w, h) * 0.39
        rgb = (0.96, 0.25, 0.37) if self._alert else ((0.06, 0.72, 0.51) if self._state == "present" else (0.96, 0.62, 0.04))

        # Crosshair axis lines
        cr.set_source_rgba(rgb[0], rgb[1], rgb[2], 0.16)
        cr.set_line_width(1.0)
        cr.move_to(cx - max_r - 8, cy); cr.line_to(cx + max_r + 8, cy)
        cr.move_to(cx, cy - max_r - 8); cr.line_to(cx, cy + max_r + 8)
        cr.stroke()

        # Degree markers & range rings
        for frac, cm_lbl in ((0.33, f"{int(self._thresh * 0.33)}"), (0.66, f"{int(self._thresh * 0.66)}"), (1.0, f"{self._thresh}cm")):
            rr = max_r * frac
            cr.set_source_rgba(rgb[0], rgb[1], rgb[2], 0.28)
            cr.new_sub_path()
            cr.arc(cx, cy, rr, 0, math.tau)
            cr.stroke()
            cr.set_source_rgba(0.80, 0.85, 0.90, 0.68)
            cr.set_font_size(8.5)
            cr.move_to(cx + 4, cy + rr - 3)
            cr.show_text(cm_lbl)

        # Polar sweep sector
        cr.set_source_rgba(rgb[0], rgb[1], rgb[2], 0.16)
        cr.move_to(cx, cy)
        cr.arc(cx, cy, max_r, self._sweep, self._sweep + 0.55)
        cr.close_path()
        cr.fill()

        # Target dot proportional to measured distance
        frac_d = min(1.0, max(0.08, self._dist / float(self._thresh))) if self._state == "present" else 0.94
        tx = cx + math.cos(-math.pi / 4.0) * (max_r * frac_d)
        ty = cy + math.sin(-math.pi / 4.0) * (max_r * frac_d)
        cr.set_source_rgba(rgb[0], rgb[1], rgb[2], 0.38)
        cr.new_sub_path()
        cr.arc(tx, ty, 10.5, 0, math.tau)
        cr.fill()
        cr.set_source_rgba(1.0, 1.0, 1.0, 0.96)
        cr.new_sub_path()
        cr.arc(tx, ty, 4.2, 0, math.tau)
        cr.fill()

        cr.set_source_rgba(0.95, 0.90, 0.92, 0.88)
        cr.set_font_size(10.5)
        cr.move_to(10, 18)
        cr.show_text(f"ToF Zone: 0..{self._thresh} cm  |  Target: {self._dist} cm ({self._state.upper()})")


class VaultWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app, title="Waylens Privacy", default_width=1140, default_height=730)
        self._busy = False
        self._latest: dict = {}

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toast_overlay = Adw.ToastOverlay()
        self.toast_overlay.set_child(root)
        self.set_content(self.toast_overlay)

        hb = Adw.HeaderBar(title_widget=Adw.WindowTitle(title="Waylens Privacy", subtitle="USB Class Inventory • Proximity Vault • Audit Trail"))
        root.append(hb)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12, margin_top=12, margin_bottom=14, margin_start=16, margin_end=16)
        root.append(body)

        # Full-Width Dynamic Threat & Action Banner (replaces 4-hero row)
        self.banner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.banner.add_css_class("threat-banner-ok")
        b_left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3, hexpand=True)
        self.b_title = Gtk.Label(label="INITIALIZING SECURITY PROBE...", xalign=0.0); self.b_title.add_css_class("banner-title")
        self.b_sub = Gtk.Label(label="Scanning /sys/bus/usb/devices, ST VL53L1 & SSH agent", xalign=0.0, wrap=True); self.b_sub.add_css_class("ss")
        b_left.append(self.b_title); b_left.append(self.b_sub)

        btn_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, valign=Gtk.Align.CENTER)
        b_trust = Gtk.Button(label="Trust Current USB"); b_trust.add_css_class("act-btn")
        b_trust.connect("clicked", self._on_trust_usb)
        b_ssh = Gtk.Button(label="Drop SSH (ssh-add -D)"); b_ssh.add_css_class("act-btn")
        b_ssh.connect("clicked", self._on_drop_ssh)
        b_clip = Gtk.Button(label="Clear Clipboard"); b_clip.add_css_class("act-btn")
        b_clip.connect("clicked", self._on_clear_clip)
        btn_bar.append(b_trust); btn_bar.append(b_ssh); btn_bar.append(b_clip)
        self.banner.append(b_left); self.banner.append(btn_bar)
        body.append(self.banner)

        # Asymmetric 3-Column Tactical Workbench
        cols = Gtk.Grid(column_spacing=12, row_spacing=12, column_homogeneous=True, vexpand=True)

        # Col 1: Polar ToF Sonar + Threshold Controls
        c1 = self._panel("ToF Proximity Perimeter", "ST VL53L1 distance telemetry & lock rules")
        self.sonar = PolarSonarCanvas()
        c1.append(self.sonar)

        thresh_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_top=6)
        self.thresh_lbl = Gtk.Label(label="Lock Threshold: 120 cm", xalign=0.0, hexpand=True); self.thresh_lbl.add_css_class("mono")
        thresh_row.append(self.thresh_lbl)
        c1.append(thresh_row)

        self.thresh_scale = Gtk.Scale.new_with_range(Gtk.Orientation.HORIZONTAL, 40, 180, 10)
        self.thresh_scale.set_value(120)
        self.thresh_scale.connect("value-changed", lambda s: self.thresh_lbl.set_label(f"Lock Threshold: {int(s.get_value())} cm"))
        c1.append(self.thresh_scale)

        for lbl_txt, attr in [("Auto-Drop SSH Keys on Away", "sw_ssh"), ("Auto-Clear Clipboard on Away", "sw_clip")]:
            sr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8, margin_top=4)
            sl = Gtk.Label(label=lbl_txt, xalign=0.0, hexpand=True); sl.add_css_class("ss")
            sw = Gtk.Switch(active=True)
            sr.append(sl); sr.append(sw)
            c1.append(sr)
            setattr(self, attr, sw)

        # Col 2: USB Physical Port & Class Matrix
        c2 = self._panel("USB Bus Inventory", "Inspects bInterfaceClass (0x03 HID, 0x08 Storage)")
        self.usb_summary = Gtk.Label(label="Baseline: scanning...", xalign=0.0); self.usb_summary.add_css_class("mono")
        c2.append(self.usb_summary)
        self.usb_rows = []
        for i in range(6):
            r = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            r.add_css_class("usb-row")
            left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, hexpand=True)
            nl = Gtk.Label(label=f"Slot {i + 1}: Empty", xalign=0.0, ellipsize=3); nl.add_css_class("mono")
            dl = Gtk.Label(label="—", xalign=0.0); dl.add_css_class("ss")
            left.append(nl); left.append(dl)
            tag = Gtk.Label(label="IDLE"); tag.add_css_class("tag-ok")
            r.append(left); r.append(tag)
            c2.append(r)
            self.usb_rows.append((nl, dl, tag))

        # Col 3: Vault State + Live SHA-256 Audit Chain
        c3 = self._panel("SSH Agent & SHA-256 Audit Chain", f"Append-only hash-linked {AUDIT_FILE.name}")
        vault_info = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.ssh_lbl = Gtk.Label(label="SSH Agent: -- keys", xalign=0.0, hexpand=True); self.ssh_lbl.add_css_class("mono")
        self.bt_lbl = Gtk.Label(label="BT: --", xalign=1.0); self.bt_lbl.add_css_class("mono")
        vault_info.append(self.ssh_lbl); vault_info.append(self.bt_lbl)
        c3.append(vault_info)

        self.audit_rows = []
        for i in range(5):
            ab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            ab.add_css_class("audit-entry")
            et = Gtk.Label(label="—", xalign=0.0, ellipsize=3); et.add_css_class("mono")
            eh = Gtk.Label(label="", xalign=0.0, ellipsize=3); eh.add_css_class("ss")
            ab.append(et); ab.append(eh)
            c3.append(ab)
            self.audit_rows.append((et, eh))

        cols.attach(c1, 0, 0, 1, 1)
        cols.attach(c2, 1, 0, 1, 1)
        cols.attach(c3, 2, 0, 1, 1)
        body.append(cols)

        GLib.timeout_add(140, self._warmup_tick)
        GLib.timeout_add(1500, self._tick)

    def _panel(self, t: str, s: str) -> Gtk.Box:
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        b.add_css_class("v-panel")
        tl = Gtk.Label(label=t, xalign=0.0); tl.add_css_class("st")
        sl = Gtk.Label(label=s, xalign=0.0); sl.add_css_class("ss")
        b.append(tl); b.append(sl)
        return b

    def _toast(self, msg: str) -> None:
        self.toast_overlay.add_toast(Adw.Toast(title=msg))

    def _on_trust_usb(self, _btn) -> None:
        devs = self._latest.get("usb_devices", [])
        keys = save_trusted_usb(devs)
        append_audit_event("USB_BASELINE_UPDATED", f"{len(keys)} trusted devices")
        self._toast(f"Saved {len(keys)} trusted USB devices")
        self._refresh()

    def _on_drop_ssh(self, _btn) -> None:
        lock_ssh_agent()
        append_audit_event("SSH_VAULT_LOCKED", "Dropped unlocked SSH identities")
        self._toast("Cleared SSH agent keys (ssh-add -D)")
        self._refresh()

    def _on_clear_clip(self, _btn) -> None:
        clear_clipboard()
        append_audit_event("CLIPBOARD_CLEARED", "Cleared Wayland/X11 clipboard")
        self._toast("Cleared clipboard")
        self._refresh()

    def _warmup_tick(self) -> bool:
        self._refresh()
        return GLib.SOURCE_REMOVE

    def _tick(self) -> bool:
        self._refresh()
        return GLib.SOURCE_CONTINUE

    def _read_audit_tail(self) -> list[dict]:
        if not AUDIT_FILE.exists():
            return []
        try:
            lines = [ln for ln in AUDIT_FILE.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
            out = []
            for ln in lines[-5:][::-1]:
                out.append(json.loads(ln))
            return out
        except Exception:
            return []

    def _refresh(self) -> None:
        if self._busy:
            return
        self._busy = True

        def _worker():
            try:
                data = probe_environment()
                audit = self._read_audit_tail()
            except Exception:
                data = None
                audit = []

            def _apply():
                self._busy = False
                if not data:
                    return GLib.SOURCE_REMOVE
                self._latest = data
                tof = data.get("tof", {})
                tst = tof.get("state", "offline")
                dist = int(tof.get("distance_cm", 0) or 0)
                thresh = int(self.thresh_scale.get_value())
                unk = data.get("unknown_usb", [])
                devs = data.get("usb_devices", [])
                trusted = data.get("trusted_usb", set())

                st_code, st_desc = evaluate_vault_state(tst, dist, unk)
                self.b_title.set_label(st_code.replace("_", " "))
                self.b_sub.set_label(f"{st_desc}  •  ToF: {dist} / {thresh} cm  •  USB: {len(devs)} attached  •  SSH: {data.get('ssh_keys_loaded', 0)} keys")

                self.banner.remove_css_class("threat-banner-ok")
                self.banner.remove_css_class("threat-banner-warn")
                self.banner.remove_css_class("threat-banner-alert")
                if unk:
                    self.banner.add_css_class("threat-banner-alert")
                elif tst == "present":
                    self.banner.add_css_class("threat-banner-ok")
                else:
                    self.banner.add_css_class("threat-banner-warn")

                self.sonar.update_state(tst, dist, thresh, bool(unk))
                self.usb_summary.set_label(
                    f"Baseline armed ({len(trusted)} allowed)  •  Alerts: {len(unk)}"
                    if trusted else
                    f"Baseline not saved ({len(devs)} USB visible — click Trust Current USB)"
                )

                for idx, (nl, dl, tag) in enumerate(self.usb_rows):
                    tag.remove_css_class("tag-ok")
                    tag.remove_css_class("tag-warn")
                    tag.remove_css_class("tag-bad")
                    if idx < len(devs):
                        d = devs[idx]
                        key = f"{d.get('port', '')}:{d.get('id', '')}"
                        is_unk = any(f"{u.get('port', '')}:{u.get('id', '')}" == key for u in unk)
                        nl.set_label(f"{d.get('product', 'USB')} ({d.get('id', '')})")
                        cls = d.get("class", "00")
                        kind = "HID/Storage" if d.get("hid_or_storage") else f"Class 0x{cls}"
                        dl.set_label(f"Port {d.get('port', '?')} • {kind}")
                        if is_unk:
                            tag.set_label("NEW/ALERT")
                            tag.add_css_class("tag-bad")
                        elif key in trusted:
                            tag.set_label("TRUSTED")
                            tag.add_css_class("tag-ok")
                        else:
                            tag.set_label("UNSAVED")
                            tag.add_css_class("tag-warn")
                    else:
                        nl.set_label(f"Port {idx + 1}: Empty")
                        dl.set_label("—")
                        tag.set_label("IDLE")
                        tag.add_css_class("tag-ok")

                self.ssh_lbl.set_label(f"SSH Keys Loaded: {data.get('ssh_keys_loaded', 0)}")
                self.bt_lbl.set_label("BT: hci0 ready" if data.get("bluetooth_ready") else "BT: offline")

                for idx, (et, eh) in enumerate(self.audit_rows):
                    if idx < len(audit):
                        rec = audit[idx]
                        et.set_label(f"[{rec.get('ts', 0)}] {rec.get('event', 'EVENT')}")
                        eh.set_label(f"{rec.get('detail', '')}  •  sha256:{str(rec.get('hash', ''))[:14]}...")
                    elif idx == 0 and not audit:
                        et.set_label("Audit chain ready (no vault actions recorded yet)")
                        eh.set_label(str(AUDIT_FILE))
                    else:
                        et.set_label("—")
                        eh.set_label("")
                return GLib.SOURCE_REMOVE

            GLib.idle_add(_apply)

        threading.Thread(target=_worker, daemon=True).start()


class VaultApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="com.lwrlock.WaylensPrivacy")

    def do_activate(self):
        p = Gtk.CssProvider()
        p.load_from_data(VAULT_CSS)
        d = Gdk.Display.get_default()
        if d:
            Gtk.StyleContext.add_provider_for_display(d, p, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        win = self.props.active_window or VaultWindow(self)
        win.present()


def main() -> int:
    return VaultApp().run(None)


if __name__ == "__main__":
    raise SystemExit(main())
