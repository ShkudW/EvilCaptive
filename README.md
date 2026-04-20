# EvilCaptive
EvilCaptive is a physical social engineering and phishing tool designed for Red Team engagements. It simulates a legitimate corporate WiFi authentication process to capture credentials and bypass MFA in real-time.

## Overview
The tool automates the creation of an Evil Twin access point (SSID). When a victim connects, they are presented with a sophisticated Microsoft-branded Captive Portal.

## How It Works
WiFi Interception: Broadcasts a fake SSID and forces a Captive Portal pop-up on the victim's device.

Credential Harvesting: A local Flask server hosts a pixel-perfect Microsoft login clone that collects the victim's username and password.

MFA Integration: The tool communicates in real-time with login.microsoftonline.com. It triggers a push notification on the victim's mobile device and retrieves the MFA Number Matching code.

Number Display: The portal displays the verification number to the victim, who then approves the request in their Microsoft Authenticator app.

Session Capture: Upon successful authentication, the tool captures and logs valid Session Cookies, allowing the operator to bypass MFA and gain access to the account.


## Key Features
Modern Auth Flow: Supports Microsoft's latest number-matching MFA.

Automated Setup: Handles DNS spoofing, DHCP, and IPTables routing out of the box.

Typosquatting Support: Configurable to run on deceptive domains (e.g., login.rnicrosfotonline.com).

Operational Logs: Saves captured cookies in a JSON format compatible with browser cookie editors.


### Installing:
```bash
sudo apt update
sudo apt install hostapd dnsmasq -y
```
### Downloading:
```bash
git clone https://github.com/ShkudW/EvilCaptive.git
cd EvilCaptive
python3 -m venv venv
source venv/bin/activate
pip install flask requests
```
### Running:
```bash
python3 run_portal.py <SSID> <Network>
python3 run_portal.py guest123 172.22.100.0
```

you can run it without argument (Default : SSID -> Office-Admin, Network -> 192.168.99.0/24
