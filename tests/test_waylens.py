import json
import pathlib
import tempfile
import unittest
from waylens.vault import (
    append_audit_event,
    detect_untrusted_usb,
    evaluate_vault_state,
    load_trusted_usb,
    save_trusted_usb,
)


class WaylensTests(unittest.TestCase):
    def test_usb_whitelist_and_badusb_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            tp = pathlib.Path(tmp) / "trust.json"
            devs = [{"port": "3-1", "id": "8087:0033", "product": "Intel BT", "hid_or_storage": False}]
            keys = save_trusted_usb(devs, path=tp)
            loaded = load_trusted_usb(path=tp)
            self.assertEqual(keys, loaded)
            self.assertEqual(detect_untrusted_usb(devs, loaded), [])

            rogue = devs + [{"port": "3-4", "id": "1337:beef", "product": "Evil HID", "hid_or_storage": True}]
            alerts = detect_untrusted_usb(rogue, loaded)
            self.assertEqual(len(alerts), 1)
            code, _ = evaluate_vault_state("present", 45, alerts)
            self.assertEqual(code, "USB_INTRUSION_LOCK")

    def test_hash_chained_audit_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            ap = pathlib.Path(tmp) / "audit.jsonl"
            h1 = append_audit_event("BOOT", "Guard armed", audit_path=ap)
            h2 = append_audit_event("LOCK", "Away lock", audit_path=ap)
            lines = [json.loads(x) for x in ap.read_text().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertEqual(lines[1]["prev"], h1)
            self.assertEqual(lines[1]["hash"], h2)


if __name__ == "__main__":
    unittest.main()
