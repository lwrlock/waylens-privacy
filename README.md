# Waylens Privacy

[![License: MIT](https://img.shields.io/badge/License-MIT-crimson.svg)](LICENSE)
[![Security: Anti-BadUSB + ToF Radar](https://img.shields.io/badge/Security-ToF%20%2B%20USB%20Vault-f43f5e.svg)](#architecture)
[![UI: GTK4 Security Console](https://img.shields.io/badge/UI-GTK4%20%2B%20Cairo-fb7185.svg)](#)

**Hardware-backed Linux Zero-Trust Proximity Vault & Anti-BadUSB Monitor combining ST VL53L1 IR ToF radar, USB interface class whitelisting (`HID`/`Mass Storage`), instant `ssh-agent` key dropping, and a SHA-256 hash-chained audit trail.**

<p align="center">
  <img src="docs/screenshots/showcase.gif" alt="Waylens Privacy Security Radar Showcase" width="900"/>
</p>

## Core Security Capabilities

- **Zero-Trust ToF Radar (`ST VL53L1`):** Tracks operator presence and millimeter distance continuously; locks session & arms vault automatically when leaving the desk.
- **Anti-BadUSB / Rubber Ducky Guard:** Native C USB enumerator inspects `bInterfaceClass` across active ports and flags unexpected HID keyboards (`0x03`) or storage (`0x08`) outside the trusted baseline (`USB_INTRUSION_LOCK`).
- **One-Click SSH Agent & Clipboard Vault:** Automatically drops unlocked SSH identities (`ssh-add -D`) and clears Wayland/X11 clipboard contents upon departure or intrusion.
- **Tamper-Evident Audit Chain:** Appends SHA-256 hash-linked JSONL records (`~/.local/share/waylens-privacy/audit.jsonl`, `0600`) for every perimeter state transition.

## Build & Run

```bash
make all && make test
./waylens-probe --json
PYTHONPATH=src /usr/bin/python3 -m waylens.gui
```

## License

MIT License — Copyright (c) 2026 Furkan (**lwrlock**). Built with assistance from Google DeepMind Antigravity.
