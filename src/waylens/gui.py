from __future__ import annotations

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
    evaluate_vault_state,
    lock_ssh_agent,
    probe_environment,
    save_trusted_usb,
)

VAULT_CSS = b"""
window, window.background, AdwApplicationWindow {
    background-color: #0b070c;
    background-image: radial-gradient(circle at 22% 20%, rgba(244, 63, 94, 0.14), transparent 48%),
                      radial-gradient(circle at 82% 82%, rgba(16, 185, 129, 0.10), transparent 48%);
    color: #fff1f2;
}
headerbar, AdwHeaderBar {
    background: rgba(16, 9, 18, 0.92);
    border-bottom: 1px solid rgba(244, 63, 94, 0.25);
    color: #fff1f2;
}
.v-card {
    background: rgba(18, 11, 20, 0.94);
    border: 1px solid rgba(244, 63, 94, 0.24);
    border-radius: 16px;
    padding: 15px 18px;
}
.v-hero {
    background: rgba(21, 13, 24, 0.95);
    border: 1px solid rgba(251, 113, 133, 0.28);
    border-radius: 15px;
    padding: 14px 16px;
}
.hk { font-size: 10.5px; font-weight: 700; color: #fb7185; letter-spacing: 0.7px; }
.hv { font-size: 23px; font-weight: 800; color: #f8fafc; }
.hs { font-size: 11.5px; color: #94a3b8; }
.st { font-size: 14px; font-weight: 700; color: #fff1f2; }
.ss { font-size: 11.5px; color: #94a3b8; }
.row { padding: 6px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.06); }
.pill-btn {
    border-radius: 9999px; padding: 6px 14px; font-weight: 600;
    background: rgba(244, 63, 94, 0.18); border: 1px solid rgba(251, 113, 133, 0.38);
}
.pill-btn:hover { background: rgba(244, 63, 94, 0.34); }
"""


class RadarPerimeterCanvas(Gtk.DrawingArea):
    """Draws concentric ToF security radar zone with live target marker and sweep."""

    def __init__(self) -> None:
        super().__init__()
        self.set_size_request(-1, 220)
        self.set_hexpand(True)
        self._dist = 50
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
        cr.set_source_rgba(0.05, 0.03, 0.06, 0.92)
        cr.rectangle(0, 0, w, h)
        cr.fill()
        cx, cy = w * 0.5, h * 0.52
        max_r = min(w, h) * 0.41
        rgb = (0.96, 0.25, 0.37) if self._alert else ((0.06, 0.72, 0.51) if self._state == "present" else (0.96, 0.62, 0.04))

        for frac in (0.33, 0.66, 1.0):
            cr.set_source_rgba(rgb[0], rgb[1], rgb[2], 0.24)
            cr.set_line_width(1.2)
            cr.new_sub_path()
            cr.arc(cx, cy, max_r * frac, 0, math.tau)
            cr.stroke()

        # Rotating radar sweep cone
        cr.set_source_rgba(rgb[0], rgb[1], rgb[2], 0.14)
        cr.move_to(cx, cy)
        cr.arc(cx, cy, max_r, self._sweep, self._sweep + 0.55)
        cr.close_path()
        cr.fill()

        # Target dot proportional to ToF distance
        frac_d = min(1.0, max(0.08, self._dist / float(self._thresh))) if self._state == "present" else 0.92
        tx = cx + math.cos(-math.pi / 4.0) * (max_r * frac_d)
        ty = cy + math.sin(-math.pi / 4.0) * (max_r * frac_d)
        cr.set_source_rgba(rgb[0], rgb[1], rgb[2], 0.35)
        cr.new_sub_path()
        cr.arc(tx, ty, 11.0, 0, math.tau)
        cr.fill()
        cr.set_source_rgba(1.0, 1.0, 1.0, 0.95)
        cr.new_sub_path()
        cr.arc(tx, ty, 4.5, 0, math.tau)
        cr.fill()

        cr.set_source_rgba(0.95, 0.90, 0.92, 0.85)
        cr.set_font_size(11.0)
        cr.move_to(12, 20)
        cr.show_text(f"Zone: 0..{self._thresh} cm  •  Target: {self._dist} cm ({self._state.upper()})")


class VaultWindow(Adw.ApplicationWindow):
    def __init__(self, app: Adw.Application) -> None:
        super().__init__(application=app, title="Waylens Privacy", default_width=1080, default_height=740)
        self._busy = False
        self._latest: dict = {}

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.toast_overlay = Adw.ToastOverlay()
        self.toast_overlay.set_child(root)
        self.set_content(self.toast_overlay)

        hb = Adw.HeaderBar(title_widget=Adw.WindowTitle(title="Waylens Privacy", subtitle="Zero-Trust IR ToF Presence & Anti-BadUSB Vault"))
        trust_btn = Gtk.Button(label="Trust Current USB")
        trust_btn.add_css_class("pill-btn")
        trust_btn.connect("clicked", self._on_trust_usb)
        hb.pack_end(trust_btn)
        root.append(hb)

        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14, margin_top=14, margin_bottom=16, margin_start=18, margin_end=18)
        root.append(body)

        hero = Gtk.Grid(column_spacing=12, row_spacing=12, column_homogeneous=True)
        c1, self.h_state, self.h_state_s = self._hero("PERIMETER STATE", "ARMED", "Evaluating sensors...")
        c2, self.h_tof, self.h_tof_s = self._hero("TOF RADAR", "-- cm", "Intel ISH ST VL53L1")
        c3, self.h_usb, self.h_usb_s = self._hero("USB TRUST GUARD", "0 Devices", "Anti-BadUSB Baseline")
        c4, self.h_ssh, self.h_ssh_s = self._hero("SSH VAULT", "0 Keys", "Agent Auto-Lock Ready")
        for i, c in enumerate((c1, c2, c3, c4)):
            hero.attach(c, i, 0, 1, 1)
        body.append(hero)

        mid = Gtk.Grid(column_spacing=14, row_spacing=14, column_homogeneous=True)
        left = self._card("Hardware Proximity Perimeter", "Live ST VL53L1 radar + Bluetooth proximity boundary")
        self.radar = RadarPerimeterCanvas()
        left.append(self.radar)

        sw_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10, margin_top=6)
        sw_lbl = Gtk.Label(label="Auto-Drop SSH Agent Keys & Clear Clipboard on Away", xalign=0.0, hexpand=True)
        self.auto_ssh_sw = Gtk.Switch(active=True)
        sw_row.append(sw_lbl); sw_row.append(self.auto_ssh_sw)
        left.append(sw_row)

        panic_btn = Gtk.Button(label="Drop Unlocked SSH Keys Now (ssh-add -D)", margin_top=6)
        panic_btn.add_css_class("pill-btn")
        panic_btn.connect("clicked", lambda *_: (lock_ssh_agent(), append_audit_event("SSH_VAULT_LOCKED", "Manual vault clear"), self._toast("✓ Cleared unlocked SSH keys.")))
        left.append(panic_btn)

        right = self._card("USB Bus Trust Inventory & Tamper-Evident Audit", "Flags unknown HID keyboards (0x03) or mass storage (0x08)")
        self.usb_rows = []
        for i in range(6):
            r = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            r.add_css_class("row")
            nl = Gtk.Label(label=f"Slot {i + 1}: Scanning...", xalign=0.0, hexpand=True)
            vl = Gtk.Label(label="—", xalign=1.0)
            vl.add_css_class("ss")
            r.append(nl); r.append(vl)
            right.append(r)
            self.usb_rows.append((nl, vl))
        self.audit_lbl = Gtk.Label(label=f"Hash-chained log: {AUDIT_FILE.name}", xalign=0.0, margin_top=6)
        self.audit_lbl.add_css_class("ss")
        right.append(self.audit_lbl)

        mid.attach(left, 0, 0, 1, 1)
        mid.attach(right, 1, 0, 1, 1)
        body.append(mid)

        GLib.timeout_add(1600, self._tick)
        self._refresh()

    def _hero(self, k: str, v: str, s: str):
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        b.add_css_class("v-hero")
        kl = Gtk.Label(label=k, xalign=0.0); kl.add_css_class("hk")
        vl = Gtk.Label(label=v, xalign=0.0); vl.add_css_class("hv")
        sl = Gtk.Label(label=s, xalign=0.0, ellipsize=3); sl.add_css_class("hs")
        b.append(kl); b.append(vl); b.append(sl)
        return b, vl, sl

    def _card(self, t: str, s: str) -> Gtk.Box:
        b = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        b.add_css_class("v-card")
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
        self._toast(f"✓ Whitelisted {len(keys)} connected USB devices.")
        self._refresh()

    def _tick(self) -> bool:
        self._refresh()
        return GLib.SOURCE_CONTINUE

    def _refresh(self) -> None:
        if self._busy:
            return
        self._busy = True

        def _worker():
            try:
                data = probe_environment()
            except Exception:
                data = None

            def _apply():
                self._busy = False
                if not data:
                    return GLib.SOURCE_REMOVE
                self._latest = data
                tof = data.get("tof", {})
                tst = tof.get("state", "offline")
                dist = int(tof.get("distance_cm", 0) or 0)
                thresh = int(tof.get("threshold_cm", 120) or 120)
                unk = data.get("unknown_usb", [])
                devs = data.get("usb_devices", [])
                trusted = data.get("trusted_usb", set())

                st_code, st_desc = evaluate_vault_state(tst, dist, unk)
                self.h_state.set_label(st_code.replace("_", " ").title())
                self.h_state_s.set_label(st_desc)
                self.h_tof.set_label(f"{dist} cm" if tst != "offline" else "Standby")
                self.h_tof_s.set_label(f"State: {tst} • Limit {thresh} cm")
                self.h_usb.set_label(f"{len(unk)} Alerts" if unk else f"{len(devs)} Verified")
                self.h_usb_s.set_label("Baseline Set" if trusted else "Click 'Trust Current USB' to arm")
                self.h_ssh.set_label(f"{data.get('ssh_keys_loaded', 0)} Unlocked")
                self.h_ssh_s.set_label("BT: hci0 ready" if data.get("bluetooth_ready") else "BT: offline")

                self.radar.update_state(tst, dist, thresh, bool(unk))
                for idx, (nl, vl) in enumerate(self.usb_rows):
                    if idx < len(devs):
                        d = devs[idx]
                        key = f"{d.get('port', '')}:{d.get('id', '')}"
                        badge = "UNTRUSTED!" if any(f"{u.get('port','')}:{u.get('id','')}" == key for u in unk) else ("HID/Mass" if d.get("hid_or_storage") else "Bus Dev")
                        nl.set_label(f"{d.get('product', 'USB')} ({d.get('id', '')})")
                        vl.set_label(f"[{d.get('port', '')}] • {badge}")
                    else:
                        nl.set_label(f"Port {idx + 1}: Empty"); vl.set_label("—")
                return GLib.SOURCE_REMOVE

            GLib.idle_add(_apply)

        threading.Thread(target=_worker, daemon=True).start()


class VaultApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id="com.lwrlock.WaylensPrivacy")

    def do_activate(self):
        p = Gtk.CssProvider(); p.load_from_data(VAULT_CSS)
        d = Gdk.Display.get_default()
        if d:
            Gtk.StyleContext.add_provider_for_display(d, p, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        win = self.props.active_window or VaultWindow(self)
        win.present()


def main() -> int:
    return VaultApp().run(None)


if __name__ == "__main__":
    raise SystemExit(main())
