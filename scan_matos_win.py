import subprocess
from pathlib import Path
from datetime import datetime


def ps(cmd: str) -> str:
    """Exécute une commande PowerShell et renvoie stdout."""
    r = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd],
        capture_output=True,
        text=True
    )
    out = (r.stdout or "").strip()
    return out


def first_line(s: str) -> str:
    s = (s or "").strip()
    return s.splitlines()[0].strip() if s else ""


def main():
    # --- Infos machine ---
    manufacturer = first_line(ps("(Get-CimInstance Win32_ComputerSystem).Manufacturer"))
    model = first_line(ps("(Get-CimInstance Win32_ComputerSystem).Model"))

    # --- BIOS ---
    bios_version = first_line(ps("(Get-CimInstance Win32_BIOS).SMBIOSBIOSVersion"))
    bios_vendor = first_line(ps("(Get-CimInstance Win32_BIOS).Manufacturer"))

    # --- CPU ---
    cpu = first_line(ps("(Get-CimInstance Win32_Processor).Name"))

    # --- OS ---
    os_name = first_line(ps("(Get-CimInstance Win32_OperatingSystem).Caption"))
    os_build = first_line(ps("(Get-CimInstance Win32_OperatingSystem).BuildNumber"))

    # --- RAM ---
    ram_gb = first_line(ps(
        "[math]::Round(((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB), 1)"
    ))

    # --- GPU (prendre la première si plusieurs) ---
    gpu = first_line(ps("(Get-CimInstance Win32_VideoController | Select-Object -First 1 -ExpandProperty Name)"))

    # --- NIC (prendre la première carte active avec une IP) ---
    # On prend la description (souvent "Intel(R) I219-LM", etc.)
    nic = first_line(ps(
        "(Get-CimInstance Win32_NetworkAdapterConfiguration | "
        "Where-Object { $_.IPEnabled -eq $true } | "
        "Select-Object -First 1 -ExpandProperty Description)"
    ))

    # --- Disque (modèle du 1er disque physique) ---
    disk = first_line(ps("(Get-CimInstance Win32_DiskDrive | Select-Object -First 1 -ExpandProperty Model)"))

    # --- Carte mère ---
    baseboard = first_line(ps("(Get-CimInstance Win32_BaseBoard).Product"))
    baseboard_vendor = first_line(ps("(Get-CimInstance Win32_BaseBoard).Manufacturer"))

    # --- Sortie fichier ---
    lines = []
    lines.append(f"# machine.txt generated on {datetime.now().isoformat(timespec='seconds')}")
    lines.append(f"Manufacturer: {manufacturer}")
    lines.append(f"Model: {model}")
    lines.append(f"Baseboard Manufacturer: {baseboard_vendor}")
    lines.append(f"Baseboard: {baseboard}")
    lines.append(f"BIOS Vendor: {bios_vendor}")
    lines.append(f"BIOS Version: {bios_version}")
    lines.append(f"CPU: {cpu}")
    lines.append(f"RAM (GB): {ram_gb}")
    lines.append(f"GPU: {gpu}")
    lines.append(f"NIC: {nic}")
    lines.append(f"Disk: {disk}")
    lines.append(f"OS: {os_name}")
    lines.append(f"OS Build: {os_build}")
    lines.append("")

    out_path = Path("machine.txt")
    out_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"✅ Fichier généré : {out_path.resolve()}")


if __name__ == "__main__":
    main()
