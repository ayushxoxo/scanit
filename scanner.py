# <--- BEGIN scanner.py (UPGRADED PHASE-1) --->
#!/usr/bin/env python3
"""
scanner.py - Phase-1 upgraded
- auto-venv (Windows)
- expanded OUI lookup using data/ouis.json
- HTTPS cert CN extraction
- deeper HTML parsing (title/meta/scripts)
- SSDP/UPnP fetch & XML parse for model/serial
- simple probability engine => manufacturer_guess + confidence
- OneDrive detection warning
"""
import os, sys, json, subprocess, socket, datetime, re, time
from pathlib import Path
from urllib.parse import urlparse

# ---- auto-venv bootstrap (unchanged pattern) ----
PROJECT_DIR = Path(os.path.abspath(os.path.dirname(__file__)))
VENV_DIR = PROJECT_DIR / "venv"
REQUIREMENTS = PROJECT_DIR / "requirements.txt"
DATA_DIR = PROJECT_DIR / "data"
REPORT_DIR = PROJECT_DIR / "reports"
MATRIX_FILE = PROJECT_DIR / "device_matrix.csv"

REQUIRED_PACKAGES = [
    "requests>=2.0",
    "pysnmp>=4.4",
    "cryptography>=3.4"   # for TLS cert extraction via ssl module fallback
]

def ensure_requirements_file():
    if REQUIREMENTS.exists():
        return
    with open(REQUIREMENTS, "w", encoding="utf-8") as f:
        for p in REQUIRED_PACKAGES:
            f.write(p + "\n")
    print("[+] Created requirements.txt")

def ensure_venv_and_rerun():
    if not VENV_DIR.exists():
        print("[+] Creating venv...")
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    # Are we already inside venv?
    running_in_venv = str(Path(sys.executable)).lower().startswith(str(VENV_DIR).lower())
    if not running_in_venv:
        # install and rerun inside venv
        pip_exe = str(VENV_DIR / "Scripts" / "pip.exe")
        print("[+] Installing dependencies inside venv...")
        subprocess.run([pip_exe, "install", "-r", str(REQUIREMENTS)], check=True)
        python_exe = str(VENV_DIR / "Scripts" / "python.exe")
        print("[+] Re-running inside venv...")
        subprocess.run([python_exe, __file__])
        sys.exit(0)

# run bootstrap if invoked directly
if __name__ == "__main__":
    ensure_requirements_file()
    ensure_venv_and_rerun()

# ---- now inside venv ----
try:
    import requests
except Exception:
    requests = None

try:
    from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd
    PYSNMP = True
except Exception:
    PYSNMP = False

import ssl
import certifi
from xml.etree import ElementTree as ET

# ---- helpers ----
def now_ts():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL).strip()
    except:
        return ""

def warn_on_onedrive():
    # If running in OneDrive folders, warn the user.
    p = PROJECT_DIR.as_posix().lower()
    if "onedrive" in p:
        print("[!] Warning: project is inside OneDrive. Move it outside to avoid venv execution issues.")

def ensure_data_files():
    DATA_DIR.mkdir(exist_ok=True)
    # create seed ouis.json if missing
    ouis_file = DATA_DIR / "ouis.json"
    if not ouis_file.exists():
        seed = {
            "E865D4": "Tenda Technology Co., Ltd.",
            "80071B": "Tenda Technology Co., Ltd.",
            "001A2B": "TP-Link Corporation",
            "001B63": "Netgear Inc.",
            "000D6F": "Linksys"
        }
        ouis_file.write_text(json.dumps(seed, indent=2), encoding="utf-8")
    # create patterns
    patterns_file = DATA_DIR / "patterns.json"
    if not patterns_file.exists():
        patterns = {"patterns":[
            {"vendor":"Tenda","match":["/goform/","tenda"]},
            {"vendor":"D-Link","match":["/cgi-bin/webproc","hnap"]},
            {"vendor":"TP-Link","match":["tplink","tp-link"]},
            {"vendor":"Netgear","match":["netgear"]},
            {"vendor":"TOTOLINK","match":["totolink"]}
        ]}
        patterns_file.write_text(json.dumps(patterns, indent=2), encoding="utf-8")

ensure_data_files()
warn_on_onedrive()

# ---- network helpers ----
def get_gateway_windows():
    out = run_cmd("ipconfig")
    for line in out.splitlines():
        if "Default Gateway" in line:
            parts = line.split(":")
            if len(parts)>=2:
                cand = parts[1].strip()
                if cand and "." in cand:
                    return cand
    return None

def get_mac_for_ip(ip):
    out = run_cmd("arp -a")
    for line in out.splitlines():
        if ip in line:
            toks = line.split()
            for tok in toks:
                if "-" in tok and len(tok.replace("-",""))==12:
                    return tok.replace("-", ":").lower()
    return None

def canonical_mac(raw):
    if not raw:
        return None
    m = re.search(r"([0-9a-fA-F]{2}[:\-]){5}([0-9a-fA-F]{2})", raw)
    if m:
        return m.group(0).replace("-", ":").lower()
    return raw.lower()

def oui_from_mac(mac):
    if not mac:
        return None
    return mac.replace(":","").upper()[:6]

def load_ouis():
    p = DATA_DIR / "ouis.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except:
        return {}

def load_patterns():
    p = DATA_DIR / "patterns.json"
    try:
        return json.loads(p.read_text(encoding="utf-8")).get("patterns",[])
    except:
        return []

# ---- HTTP + TLS probing ----
def probe_http_deep(ip):
    results = {}
    urls = [f"http://{ip}/", f"https://{ip}/", f"http://{ip}/cgi-bin/luci", f"http://{ip}/login", f"http://{ip}/index.asp"]
    for u in urls:
        try:
            if u.startswith("https://"):
                r = requests.get(u, timeout=3, verify=False)
            else:
                r = requests.get(u, timeout=3)
            txt = r.text
            # headers
            headers = {k.lower():v for k,v in r.headers.items()}
            if headers:
                results.setdefault("headers",{}).update(headers)
            # title
            mt = re.search(r"<title>(.*?)</title>", txt, re.I|re.S)
            if mt:
                results.setdefault("html",{})["title"] = mt.group(1).strip()
            # meta
            metas = re.findall(r"<meta[^>]+>", txt, re.I|re.S)
            for m in metas:
                c = re.search(r'content=["\']([^"\']+)', m, re.I)
                n = re.search(r'(name|property)=["\']?([^"\'> ]+)', m, re.I)
                if c and n:
                    key = n.group(2).lower()
                    results.setdefault("meta",{})[key] = c.group(1)
            # search JS for model/serial variables
            js_matches = re.findall(r'var\s+([a-zA-Z0-9_\-]+)\s*=\s*["\']([^"\']{3,80})["\']', txt)
            for k,v in js_matches:
                kl = k.lower()
                if any(x in kl for x in ("model","product","serial","hw","fw","version")):
                    results.setdefault("js",{})[k]=v
            # save url + status
            results["url"] = u
            results["status_code"] = r.status_code
            if results:
                return results
        except Exception:
            continue
    return None

def tls_cert_info(ip):
    # try to get cert CN via ssl
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip,443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                # cert may be a dict; get subject and san
                subject = cert.get('subject',())
                cn = None
                for attr in subject:
                    for k,v in attr:
                        if k.lower()=='commonname':
                            cn = v
                            break
                san = cert.get('subjectAltName',())
                return {"cn":cn,"san":san}
    except Exception:
        return None

# ---- SSDP / UPnP ----
def ssdp_msearch(timeout=2):
    MCAST = ("239.255.255.250", 1900)
    msg = '\r\n'.join(['M-SEARCH * HTTP/1.1',
                       'HOST: 239.255.255.250:1900',
                       'MAN: "ssdp:discover"',
                       'MX: 1',
                       'ST: ssdp:all',
                       '', '']).encode('utf-8')
    res = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.settimeout(timeout)
    try:
        s.sendto(msg, MCAST)
        start = time.time()
        while time.time()-start < timeout:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            text = data.decode(errors='ignore')
            headers = {}
            for line in text.splitlines()[1:]:
                if ":" in line:
                    k,v = line.split(":",1)
                    headers[k.strip().lower()] = v.strip()
            headers["from"] = addr[0]
            res.append(headers)
    finally:
        s.close()
    return res if res else None

def fetch_upnp_device_xml(location):
    try:
        r = requests.get(location, timeout=3)
        if r.status_code==200:
            xml = r.text
            # parse modelName and serialNumber
            md = {}
            m = re.search(r"<modelName>(.*?)</modelName>", xml, re.I|re.S)
            if m:
                md["modelName"] = m.group(1).strip()
            s = re.search(r"<serialNumber>(.*?)</serialNumber>", xml, re.I|re.S)
            if s:
                md["serialNumber"] = s.group(1).strip()
            return md
    except Exception:
        pass
    return None

# ---- SNMP probe ----
def snmp_probe(ip):
    if not PYSNMP:
        return None
    out = {}
    try:
        for (name,mib,oid) in [("sysName","SNMPv2-MIB","sysName"),("sysDescr","SNMPv2-MIB","sysDescr")]:
            it = getCmd(SnmpEngine(), CommunityData('public', mpModel=0), UdpTransportTarget((ip,161), timeout=1, retries=0), ContextData(), ObjectType(ObjectIdentity(mib, oid, 0)))
            errInd, errStat, errIdx, varBinds = next(it)
            if not errInd and not errStat:
                out[name] = str(varBinds[0][1])
    except Exception:
        return None
    return out if out else None

# ---- matrix helpers ----
def ensure_matrix_exists():
    if MATRIX_FILE.exists():
        return
    rows = [
        "TP-Link,Archer C7,supported,Archer C7 v5 (Atheros)",
        "Tenda,,partial,Tenda family (verify model)",
        "Netgear,,partial,Netgear family - check model",
        "D-Link,,partial,D-Link family"
    ]
    with open(MATRIX_FILE,"w",encoding="utf-8") as f:
        f.write("# vendor_hint,model_hint,support,notes\n")
        for r in rows:
            f.write(r+"\n")

def read_matrix():
    ensure_matrix_exists()
    out = []
    with open(MATRIX_FILE,"r",encoding="utf-8") as f:
        for line in f:
            if line.strip()=="" or line.startswith("#"): continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts)<3: continue
            out.append({"vendor_hint":parts[0],"model_hint":parts[1],"support":parts[2],"notes":parts[3] if len(parts)>3 else ""})
    return out

def match_matrix(manuf, fp, matrix):
    for r in matrix:
        if manuf and r["vendor_hint"].lower() in (manuf or "").lower():
            return r
        if fp and r["vendor_hint"].lower() in (fp or "").lower():
            return r
    return None

# ---- main detection flow ----
def run_scan():
    gw = get_gateway_windows()
    if not gw:
        return {"error":"no_gateway_found"}
    mac_raw = get_mac_for_ip(gw)
    mac = canonical_mac(mac_raw) if mac_raw else None
    oui = oui_from_mac(mac) if mac else None
    ouis = load_ouis()
    vendor_guess = ouis.get(oui, None)

    http = probe_http_deep(gw) if requests else None
    tls = tls_cert_info(gw)
    ssdp = ssdp_msearch()
    snmp = snmp_probe(gw)

    # derive manufacturer/model/serial
    manufacturer = vendor_guess
    model = None
    serial = None
    fp = None
    # from HTTP
    if http:
        fp = http.get("html",{}).get("title") or http.get("headers",{}).get("server")
        meta = http.get("meta",{})
        if meta:
            for k,v in meta.items():
                kl = k.lower()
                if "model" in kl or "product" in kl:
                    model = model or v
                if "serial" in kl:
                    serial = serial or v
    # from TLS
    if tls:
        cn = tls.get("cn")
        if cn:
            fp = fp or cn
            # try to collect manufacturer from CN tokens
            for token in ("tenda","tplink","netgear","dlink","asus"):
                if token in (cn or "").lower():
                    manufacturer = manufacturer or token.capitalize()
    # from SSDP
    if ssdp:
        for e in ssdp:
            if e.get("server"):
                if not manufacturer:
                    manufacturer = (e.get("server") or "").split("/")[0]
            if e.get("location"):
                xml = fetch_upnp_device_xml(e.get("location"))
                if xml:
                    model = model or xml.get("modelName")
                    serial = serial or xml.get("serialNumber")

    # SNMP
    if snmp:
        manufacturer = manufacturer or (snmp.get("sysDescr") and snmp.get("sysDescr").split()[0])
        model = model or snmp.get("sysName")
    # pattern matching
    patterns = load_patterns()
    combined_text = " ".join(filter(None,[fp, manufacturer, model, str(http)]))
    probable = None
    for p in patterns:
        for tok in p.get("match",[]):
            if tok.lower() in combined_text.lower():
                probable = p.get("vendor")
                manufacturer = manufacturer or probable
                break
        if probable: break

    # probability/confidence: simple heuristic
    confidence = 0.5
    if manufacturer: confidence += 0.2
    if model: confidence += 0.2
    if fp: confidence += 0.1
    if snmp: confidence += 0.1
    confidence = min(confidence, 0.95)

    matrix = read_matrix()
    matrix_match = match_matrix(manufacturer, fp, matrix)

    # simple scoring for OpenWrt-friendliness
    score = 50
    if fp and "openwrt" in (fp or "").lower(): score += 35
    if snmp: score += 5
    if not (http or tls or snmp or ssdp): score -= 10
    score = max(0, min(100, score))

    # auto-suggest matrix entry if not matched
    if not matrix_match and manufacturer:
        with open(MATRIX_FILE,"r",encoding="utf-8") as f:
            content = f.read().lower()
        if manufacturer.lower() not in content:
            with open(MATRIX_FILE,"a",encoding="utf-8") as f:
                f.write(f"#AUTO,{manufacturer},{model or ''},partial,auto-suggested {now_ts()} score={score}\n")

    # final report
    report = {
        "timestamp": now_ts(),
        "gateway": gw,
        "mac": mac,
        "oui": oui,
        "vendor_guess": vendor_guess,
        "manufacturer": manufacturer,
        "model": model,
        "serial_exposed": serial,
        "http": http,
        "tls_cert": tls,
        "ssh_banner": None,
        "telnet": False,
        "ssdp": ssdp,
        "snmp": snmp,
        "matrix_match": matrix_match,
        "probable_vendor": probable,
        "confidence": round(confidence,2),
        "score": score
    }
    return report

# ---- run and save ----
if __name__ == "__main__":
    REPORT_DIR.mkdir(exist_ok=True)
    ensure_matrix_exists()
    print("[*] Running Phase-1 upgraded scan...")
    res = run_scan()
    out = REPORT_DIR / f"report_{now_ts()}.json"
    with open(out,"w",encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    print("[+] Report saved to:", out)
    print("Summary:", {"manufacturer": res.get("manufacturer"), "model": res.get("model"), "confidence": res.get("confidence"), "score": res.get("score")})
# <--- END scanner.py --->
