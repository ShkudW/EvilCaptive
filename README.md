# EvilCaptive
Python Tool for Physical phishing
the tool will exctrating JSON file with valid cookies after full authentication (with MFA approvment)

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
