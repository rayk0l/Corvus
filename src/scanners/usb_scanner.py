"""
usb_scanner.py - USB device history analysis module.

Enumerates USB device history from Windows Registry to detect:
  1. Known BadUSB/malicious hardware (Rubber Ducky, USB Armory, etc.)
  2. Composite HID+Storage devices (BadUSB indicators)
  3. USB-to-Network adapters (rogue network devices)
  4. USB mass storage inventory (forensic value)

All data is read from the registry — fully read-only, no system changes.
"""

import os
import winreg
from typing import List, Dict, Set, Optional, Tuple
from datetime import datetime

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    print_section, print_finding,
)


# ---------------------------------------------------------------------------
# Known BadUSB / Suspicious Hardware Indicators
# ---------------------------------------------------------------------------

# (vid_lower, pid_lower) → description
KNOWN_BADUSB_DEVICES: Dict[Tuple[str, str], str] = {
    # Hak5 tools
    ("vid_16d0", "pid_0753"): "Hak5 USB Rubber Ducky",
    ("vid_16d0", "pid_0bda"): "Hak5 Bash Bunny",
    ("vid_16d0", "pid_0c02"): "Hak5 Packet Squirrel",
    ("vid_16d0", "pid_0c04"): "Hak5 Key Croc",
    ("vid_16d0", "pid_0c05"): "Hak5 Screen Crab",
    ("vid_16d0", "pid_0c06"): "Hak5 Shark Jack",
    # Arduino/microcontroller HID devices (commonly used for BadUSB)
    ("vid_2341", "pid_8037"): "Arduino Leonardo (HID injection capable)",
    ("vid_2341", "pid_8036"): "Arduino Leonardo bootloader (HID capable)",
    ("vid_1b4f", "pid_9205"): "SparkFun Pro Micro (HID injection capable)",
    ("vid_1b4f", "pid_9206"): "SparkFun Pro Micro bootloader",
    # Raspberry Pi Pico (BadUSB capable with CircuitPython)
    ("vid_2e8a", "pid_0005"): "Raspberry Pi Pico (BadUSB capable)",
    ("vid_2e8a", "pid_000a"): "Raspberry Pi Pico W (BadUSB capable)",
    # USB Armory
    ("vid_1d6b", "pid_0137"): "USB Armory (security research device)",
    # Teensy (common BadUSB platform)
    ("vid_16c0", "pid_0486"): "Teensy USB HID device (BadUSB capable)",
    ("vid_16c0", "pid_0487"): "Teensy MIDI/Serial (BadUSB capable)",
    # O.MG Cable (attack tool disguised as USB cable)
    ("vid_16d0", "pid_11a4"): "Possible O.MG Cable (attack tool)",
}

# USB device class codes that are suspicious in certain combinations
_USB_CLASS_NETWORK = {"02", "e0", "ef"}  # CDC, Wireless, Misc (RNDIS)
_USB_CLASS_HID = {"03"}
_USB_CLASS_STORAGE = {"08"}


# ---------------------------------------------------------------------------
# Registry Reading Helpers
# ---------------------------------------------------------------------------

def _enum_subkeys(hkey: int, path: str) -> List[str]:
    """Enumerate registry subkey names. Returns empty list on error."""
    subkeys = []
    try:
        with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(key, i))
                    i += 1
                except OSError:
                    break
    except (PermissionError, OSError):
        pass
    return subkeys


def _read_reg_value(hkey: int, path: str, name: str) -> Optional[str]:
    """Read a single registry string value. Returns None on error."""
    try:
        with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return str(value) if value else None
    except (PermissionError, OSError, FileNotFoundError):
        return None


def _get_device_friendly_name(device_id: str) -> str:
    """Try to find a friendly name for a USB device from Portable Devices."""
    try:
        base = r"SOFTWARE\Microsoft\Windows Portable Devices\Devices"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0,
                            winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    if device_id.lower() in subkey_name.lower():
                        name = _read_reg_value(
                            winreg.HKEY_LOCAL_MACHINE,
                            f"{base}\\{subkey_name}",
                            "FriendlyName",
                        )
                        if name:
                            return name
                    i += 1
                except OSError:
                    break
    except (PermissionError, OSError):
        pass
    return ""


# ---------------------------------------------------------------------------
# USB Device Enumeration
# ---------------------------------------------------------------------------

def _enumerate_usbstor() -> List[Dict]:
    """Enumerate USB mass storage devices from USBSTOR registry."""
    devices = []
    base_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"

    for device_class in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base_path):
        # device_class format: "Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00"
        parts = device_class.split("&")
        vendor = ""
        product = ""
        for part in parts:
            if part.lower().startswith("ven_"):
                vendor = part[4:]
            elif part.lower().startswith("prod_"):
                product = part[5:]

        class_path = f"{base_path}\\{device_class}"
        for serial in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, class_path):
            friendly = _read_reg_value(
                winreg.HKEY_LOCAL_MACHINE,
                f"{class_path}\\{serial}",
                "FriendlyName",
            ) or f"{vendor} {product}".strip()

            devices.append({
                "type": "USBSTOR",
                "vendor": vendor,
                "product": product,
                "serial": serial,
                "friendly_name": friendly,
                "registry_path": f"{class_path}\\{serial}",
            })

    return devices


def _enumerate_usb_devices() -> List[Dict]:
    """Enumerate all USB devices from USB registry (VID/PID level)."""
    devices = []
    base_path = r"SYSTEM\CurrentControlSet\Enum\USB"

    for vid_pid in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, base_path):
        vid_pid_lower = vid_pid.lower()

        # Extract VID and PID
        vid = ""
        pid = ""
        for part in vid_pid_lower.split("&"):
            if part.startswith("vid_"):
                vid = part
            elif part.startswith("pid_"):
                pid = part

        class_path = f"{base_path}\\{vid_pid}"
        for instance in _enum_subkeys(winreg.HKEY_LOCAL_MACHINE, class_path):
            # Read compatible IDs to determine device class
            compat_ids = _read_reg_value(
                winreg.HKEY_LOCAL_MACHINE,
                f"{class_path}\\{instance}",
                "CompatibleIDs",
            ) or ""

            device_desc = _read_reg_value(
                winreg.HKEY_LOCAL_MACHINE,
                f"{class_path}\\{instance}",
                "DeviceDesc",
            ) or ""

            # Extract USB class from compatible IDs
            usb_classes: Set[str] = set()
            if isinstance(compat_ids, str):
                compat_ids = [compat_ids]
            elif not isinstance(compat_ids, (list, tuple)):
                compat_ids = []
            for cid in compat_ids:
                cid_lower = str(cid).lower()
                # Format: USB\Class_XX
                if "class_" in cid_lower:
                    cls = cid_lower.split("class_")[1][:2]
                    usb_classes.add(cls)

            devices.append({
                "type": "USB",
                "vid": vid,
                "pid": pid,
                "vid_pid": vid_pid,
                "instance": instance,
                "device_desc": device_desc,
                "usb_classes": usb_classes,
                "registry_path": f"{class_path}\\{instance}",
            })

    return devices


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _check_badusb(usb_devices: List[Dict]) -> List[Finding]:
    """Check for known BadUSB devices by VID/PID."""
    findings = []
    for dev in usb_devices:
        vid = dev.get("vid", "")
        pid = dev.get("pid", "")
        if not vid or not pid:
            continue

        key = (vid, pid)
        if key in KNOWN_BADUSB_DEVICES:
            desc_text = KNOWN_BADUSB_DEVICES[key]
            findings.append(Finding(
                module="USB Scanner",
                risk=RiskLevel.HIGH,
                title=f"Known attack hardware: {desc_text}",
                description=(
                    f"USB device with VID/PID {vid.upper()}&{pid.upper()} "
                    f"matches a known attack tool: {desc_text}. "
                    "This device can inject keystrokes or execute payloads."
                ),
                details={
                    "vid_pid": dev["vid_pid"],
                    "device_desc": dev.get("device_desc", ""),
                    "instance": dev.get("instance", ""),
                    "detection": "Known BadUSB VID/PID",
                },
                mitre_id="T1200",
                remediation=(
                    "Immediately disconnect the device. Investigate who "
                    "connected it and review system logs for unauthorized activity."
                ),
            ))

    return findings


def _check_composite_devices(usb_devices: List[Dict]) -> List[Finding]:
    """Check for composite HID+Storage devices (BadUSB indicator)."""
    findings = []
    for dev in usb_devices:
        classes = dev.get("usb_classes", set())
        has_hid = bool(classes & _USB_CLASS_HID)
        has_storage = bool(classes & _USB_CLASS_STORAGE)

        if has_hid and has_storage:
            # Skip known safe composite devices (e.g., some Logitech receivers)
            vid = dev.get("vid", "")
            if vid in ("vid_046d",):  # Logitech
                continue

            findings.append(Finding(
                module="USB Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"Composite HID+Storage USB device: {dev.get('vid_pid', '')}",
                description=(
                    "USB device presents both HID (keyboard/mouse) and Mass Storage "
                    "interfaces simultaneously. This combination is characteristic "
                    "of BadUSB devices that can inject keystrokes."
                ),
                details={
                    "vid_pid": dev["vid_pid"],
                    "device_desc": dev.get("device_desc", ""),
                    "usb_classes": sorted(classes),
                    "detection": "Composite HID+Storage",
                },
                mitre_id="T1200",
                remediation=(
                    "Verify this is a legitimate device. Composite HID+Storage "
                    "devices can be used for keystroke injection attacks."
                ),
            ))

    return findings


def _check_network_adapters(usb_devices: List[Dict]) -> List[Finding]:
    """Check for USB network adapters (potential rogue devices)."""
    findings = []
    for dev in usb_devices:
        classes = dev.get("usb_classes", set())
        has_network = bool(classes & _USB_CLASS_NETWORK)

        if has_network:
            desc = dev.get("device_desc", "").lower()
            # Skip well-known legitimate adapters
            if any(k in desc for k in ("bluetooth", "wireless mouse",
                                        "wireless keyboard")):
                continue

            findings.append(Finding(
                module="USB Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"USB network adapter: {dev.get('vid_pid', '')}",
                description=(
                    "A USB network adapter was found in device history. "
                    "Rogue USB network adapters can intercept traffic or "
                    "provide unauthorized network access."
                ),
                details={
                    "vid_pid": dev["vid_pid"],
                    "device_desc": dev.get("device_desc", ""),
                    "usb_classes": sorted(classes),
                    "detection": "USB Network Adapter",
                },
                mitre_id="T1200",
                remediation=(
                    "Verify this network adapter is authorized. "
                    "Unauthorized USB network devices can be used "
                    "for man-in-the-middle or exfiltration attacks."
                ),
            ))

    return findings


def _inventory_storage(usbstor_devices: List[Dict]) -> List[Finding]:
    """Generate inventory findings for USB mass storage devices."""
    findings = []

    if not usbstor_devices:
        return findings

    # Count unique devices by vendor+product
    unique_devices: Dict[str, List[Dict]] = {}
    for dev in usbstor_devices:
        key = f"{dev['vendor']}_{dev['product']}".lower()
        unique_devices.setdefault(key, []).append(dev)

    total_unique = len(usbstor_devices)

    # High volume of unique USB devices (data exfiltration risk)
    if total_unique > 10:
        findings.append(Finding(
            module="USB Scanner",
            risk=RiskLevel.INFO,
            title=f"High USB storage device count: {total_unique} devices",
            description=(
                f"System has history of {total_unique} unique USB mass "
                "storage devices. High device count may indicate data "
                "transfer activity."
            ),
            details={
                "total_devices": total_unique,
                "unique_models": len(unique_devices),
                "devices": [
                    f"{d['vendor']} {d['product']} (SN: {d['serial'][:16]})"
                    for d in usbstor_devices[:20]
                ],
                "detection": "USB Inventory",
            },
            mitre_id="T1052.001",
            remediation=(
                "Review USB device history for unauthorized devices. "
                "Consider implementing USB device whitelisting policies."
            ),
        ))

    # Summary finding with device list
    device_summary = [
        f"{d['friendly_name']} (SN: {d['serial'][:16]})"
        for d in usbstor_devices[:15]
    ]
    findings.append(Finding(
        module="USB Scanner",
        risk=RiskLevel.INFO,
        title=f"USB storage history: {total_unique} device(s)",
        description=(
            f"Enumerated {total_unique} USB mass storage device(s) "
            "from system registry."
        ),
        details={
            "total_devices": total_unique,
            "devices": device_summary,
            "detection": "USB Storage Inventory",
        },
        mitre_id="T1091",
        remediation="Review device list for unauthorized USB storage devices.",
    ))

    return findings


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------

def scan() -> List[Finding]:
    """Scan USB device history from Windows Registry.

    Checks for:
      1. Known BadUSB/attack hardware (Rubber Ducky, USB Armory, etc.)
      2. Composite HID+Storage devices (BadUSB indicator)
      3. USB network adapters (rogue devices)
      4. USB mass storage inventory (forensic value)
    """
    print_section("USB SCANNER - USB Device History Analysis")
    findings: List[Finding] = []

    # Enumerate USB devices from registry
    print("  [i] Enumerating USB device history from registry...")

    usbstor_devices = _enumerate_usbstor()
    usb_devices = _enumerate_usb_devices()

    print(f"  [i] Found {len(usbstor_devices)} USB storage device(s), "
          f"{len(usb_devices)} total USB device(s)")

    # Check 1: Known BadUSB devices
    badusb_findings = _check_badusb(usb_devices)
    for f in badusb_findings:
        findings.append(f)
        print_finding(f)

    # Check 2: Composite HID+Storage devices
    composite_findings = _check_composite_devices(usb_devices)
    for f in composite_findings:
        findings.append(f)
        print_finding(f)

    # Check 3: USB network adapters
    network_findings = _check_network_adapters(usb_devices)
    for f in network_findings:
        findings.append(f)
        print_finding(f)

    # Check 4: USB storage inventory
    inventory_findings = _inventory_storage(usbstor_devices)
    for f in inventory_findings:
        findings.append(f)
        print_finding(f)

    print(f"  [i] USB scan complete. {len(findings)} finding(s).")
    return findings
