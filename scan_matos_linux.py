#!/usr/bin/env python3
import os
import re
import subprocess
from pathlib import Path

OUT = "machine.txt"

def sh(cmd: list[str]) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return ""

def first_nonempty(*vals: str) -> str:
    for v in vals:
        if v and v.strip():
            return v.strip()
    return ""

def read_file(p: str) -> str:
    try:
        return Path(p).read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""

def parse_os_pretty_name() -> str:
    txt = read_file("/etc/os-release")
    m = re.search(r'^PRETTY_NAME="?(.*?)"?$', txt, re.M)
    return m.group(1) if m else ""

def detect_manufacturer_model() -> tuple[str, str]:
    # DMI (souvent OK sur laptop/desktop)
    manufacturer = first_nonempty(
        read_file("/sys/class/dmi/id/sys_vendor"),
        sh(["sudo", "-n", "dmidecode", "-s", "system-manufacturer"]),
    )
    model = first_nonempty(
        read_file("/sys/class/dmi/id/product_name"),
        sh(["sudo", "-n", "dmidecode", "-s", "system-product-name"]),
    )
    return manufacturer, model

def detect_baseboard() -> tuple[str, str]:
    base_manu = first_nonempty(
        read_file("/sys/class/dmi/id/board_vendor"),
        sh(["sudo", "-n", "dmidecode", "-s", "baseboard-manufacturer"]),
    )
    base_name = first_nonempty(
        read_file("/sys/class/dmi/id/board_name"),
        sh(["sudo", "-n", "dmidecode", "-s", "baseboard-product-name"]),
    )
    return base_manu, base_name

def detect_bios() -> tuple[str, str]:
    vendor = first_nonempty(
        read_file("/sys/class/dmi/id/bios_vendor"),
        sh(["sudo", "-n", "dmidecode", "-s", "bios-vendor"]),
    )
    version = first_nonempty(
        read_file("/sys/class/dmi/id/bios_version"),
        sh(["sudo", "-n", "dmidecode", "-s", "bios-version"]),
    )
    return vendor, version

def detect_cpu() -> str:
    # lscpu est présent sur la majorité des distros
    s = sh(["lscpu"])
    for line in s.splitlines():
        if "Model name:" in line:
            return line.split(":", 1)[1].strip()
    return first_nonempty(read_file("/proc/cpuinfo"))

def detect_ram_gb() -> str:
    mem_kb = ""
    s = read_file("/proc/meminfo")
    m = re.search(r"^MemTotal:\s+(\d+)\s+kB", s, re.M)
    if m:
        mem_kb = m.group(1)
    if mem_kb:
        gb = int(int(mem_kb) / 1024 / 1024)
        return str(gb)
    return ""

def detect_gpu() -> str:
    # pciutils (lspci) recommandé
    s = sh(["lspci"])
    gpus = []
    for line in s.splitlines():
        if re.search(r"(VGA compatible controller|3D controller|Display controller)", line, re.I):
            # enlever le préfixe "00:02.0 "
            gpus.append(re.sub(r"^[0-9a-fA-F:.]+\s+", "", line).strip())
    return ", ".join(gpus) if gpus else ""

def detect_nic() -> str:
    # Liste des cartes réseau PCI (wifi/ethernet)
    s = sh(["lspci"])
    nics = []
    for line in s.splitlines():
        if re.search(r"(Ethernet controller|Network controller|Wireless)", line, re.I):
            nics.append(re.sub(r"^[0-9a-fA-F:.]+\s+", "", line).strip())
    return ", ".join(nics) if nics else ""

def detect_disk() -> str:
    # lsblk présent quasi partout
    s = sh(["lsblk", "-dno", "MODEL,TYPE,SIZE"])
    disks = []
    for line in s.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-2] in ("disk",):  # ... MODEL TYPE SIZE
            disks.append(line.strip())
    return " | ".join(disks) if disks else ""

def main():
    manufacturer, model = detect_manufacturer_model()
    base_manu, baseboard = detect_baseboard()
    bios_vendor, bios_version = detect_bios()
    cpu = detect_cpu()
    ram = detect_ram_gb()
    gpu = detect_gpu()
    nic = detect_nic()
    disk = detect_disk()
    os_name = parse_os_pretty_name() or sh(["uname", "-sr"])

    lines = []
    if manufacturer: lines.append(f"Manufacturer: {manufacturer}")
    if model:        lines.append(f"Model: {model}")
    if base_manu:    lines.append(f"Baseboard Manufacturer: {base_manu}")
    if baseboard:    lines.append(f"Baseboard: {baseboard}")
    if bios_vendor:  lines.append(f"BIOS Vendor: {bios_vendor}")
    if bios_version: lines.append(f"BIOS Version: {bios_version}")
    if cpu:          lines.append(f"CPU: {cpu}")
    if ram:          lines.append(f"RAM (GB): {ram}")
    if gpu:          lines.append(f"GPU: {gpu}")
    if nic:          lines.append(f"NIC: {nic}")
    if disk:         lines.append(f"Disk: {disk}")
    if os_name:      lines.append(f"OS: {os_name}")

    Path(OUT).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"OK -> {OUT} généré ({len(lines)} lignes)")

if __name__ == "__main__":
    main()
