# 🔎 Scanner v2.3

An advanced Python-based network security scanner that detects **open ports, services, and banners**.  
Created with 💻 by **Anish Kushwaha (🗣 ❤️‍🔥)**.

---

## 🚀 Features
- Multi-threaded Port Scanning (Fast ⚡)
- Detects common services (FTP, SSH, HTTP, HTTPS, MySQL, etc.)
- Banner grabbing for deeper insights
- JSON Export of results
- Hacker-style terminal logs 😎

---

## 📥 Installation
```bash
#git clone #https://github.com/Anishkushwaha02/Sc#anner-v.2.3.git
#cd Scanner-v.2.3


#!/usr/bin/env python3
# 🔥 Advanced Security & Admin Panel Scanner — Terminal Edition
# 👨‍💻 Creator: Anish Kushwaha (🗣 ❤️‍🔥)
# 🚀 Fast live-scanning + admin-panel detection + JSON export
#
# WARNING: Use only on systems you own or have explicit permission to test.
# Unauthorized scanning is illegal.


#code begins:-

import socket, sys, time, argparse, json, hashlib, webbrowser, threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3
from queue import Queue
import re  # Fixed: Added missing import

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------
# Default configs
# ----------------------------
DEFAULT_TIMEOUT = 0.4
DEFAULT_WORKERS = 300
MAX_WORKERS = 1000
DEFAULT_TOP_EXTENDED = 1000

# common ports / known admin ports (broad)
KNOWN_ADMIN_PORTS_FLAT = sorted(list(set(
    [80, 443, 8080, 8443, 8888, 8000, 10000, 2082, 2083, 2095, 2096, 2222, 10001, 9000, 9443, 7000, 7080, 9080, 9090, 8880, 10443, 8243, 81, 82] 
    # you can extend this list as desired
)))

COMMON_ADMIN_PATHS = [
    "/", "/login", "/admin", "/administrator", "/admin/login", "/user/login",
    "/cpanel", "/wp-admin", "/panel", "/dashboard", "/manager", "/plesk",
    "/login.php", "/phpmyadmin", "/administrator/index.php", "/admin/index.php",
    "/server-status", "/adminarea", "/admincp"
]

ADMIN_KEYWORDS = ["admin", "login", "sign in", "control panel", "cpanel", "plesk", "webmin", "directadmin", "wp-login", "phpmyadmin", "administrator"]

PRODUCT_HEADERS = ["server", "x-powered-by"]

# ----------------------------
# Utilities
# ----------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Anish — Terminal Admin Finder (live) v2.3")
    p.add_argument("-u", "--url", help="Target URL or domain : ")
    p.add_argument("-p", "--ports", type=int, default=1000, help="Number of ports to scan (1..65535). Default 1000 (scans known admin ports + 1..N)")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help=f"Max workers (default {DEFAULT_WORKERS})")
    p.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Socket timeout (s) default {DEFAULT_TIMEOUT}")
    p.add_argument("--json", action="store_true", help="Save results to JSON at end")
    p.add_argument("--no-browser", action="store_true", help="Don't prompt to open found admin URLs")
    return p.parse_args()

def resolve_domain(url):
    try:
        if "://" not in url:
            url = "http://" + url
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        if ":" in host:
            host = host.split(":",1)[0]
        ip = socket.gethostbyname(host)
        return host, ip
    except Exception as e:
        print(f"❌ DNS resolve failed: {e}")
        return None, None

def sha256_bytes(b: bytes) -> str:
    import hashlib
    return hashlib.sha256(b).hexdigest()

# small helper (NEW - safe first line)
def first_line_or_empty(s: str) -> str:
    """
    Return the first line of s, or empty string if s has no lines.
    This replaces unsafe s.splitlines()[0].
    """
    if not s:
        return ""
    lines = s.splitlines()
    return lines[0] if lines else ""

# ----------------------------
# Network probing
# ----------------------------
def try_socket_open(ip, port, timeout, banner_host):
    """
    Return dict if open with banner/headers (possible empty), else None
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        rc = s.connect_ex((ip, port))
        if rc != 0:
            s.close()
            return None
        banner = ""
        headers = {}
        try:
            req = f"HEAD / HTTP/1.1\r\nHost: {banner_host}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("utf-8", errors="ignore"))
            data = s.recv(2048)
            if data:
                txt = data.decode(errors="ignore")
                banner = txt.strip()
                # parse headers naive
                for line in txt.splitlines()[1:]:
                    if ":" in line:
                        k, v = line.split(":",1)
                        headers[k.strip().lower()] = v.strip()
        except Exception:
            pass
        s.close()
        return {"banner": banner, "socket_headers": headers}
    except Exception:
        return None

def http_probe_for_admin(ip, port, domain_host, timeout):
    """
    Try HTTP/HTTPS GET to a list of admin paths and return matches list
    """
    headers = {"User-Agent": "Mozilla/5.0 (Anish-AdminFinder)"}
    results = []
    schemes = ["http", "https"]
    # decide order: ports usually linked to https (443,8443)
    if port in (443, 8443, 9443, 10443):
        schemes = ["https", "http"]
    for scheme in schemes:
        base = f"{scheme}://{ip}:{port}"
        for path in COMMON_ADMIN_PATHS:
            url = base + path
            try:
                r = requests.get(url, headers={**headers, "Host": domain_host}, timeout=5, verify=False, allow_redirects=True)
                status = r.status_code
                text = r.text[:4000]
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE|re.DOTALL)
                if m:
                    title = m.group(1).strip()
                body = (title + " " + (text or "")).lower()
                matched = [kw for kw in ADMIN_KEYWORDS if kw in body]
                if matched or status in (401,403):
                    results.append({
                        "url": url,
                        "status": status,
                        "title": title,
                        "keywords": matched,
                        "server_headers": {k: r.headers.get(k,"") for k in PRODUCT_HEADERS}
                    })
            except requests.RequestException:
                continue
    return results if results else None

# ----------------------------
# Live scanning worker
# ----------------------------
def scan_port_worker(ip, port, timeout, domain_host, out_q):
    try:
        info = try_socket_open(ip, port, timeout, domain_host)
        if not info:
            return
        item = {
            "port": port,
            "banner": info.get("banner",""),
            "socket_headers": info.get("socket_headers",{}),
            "http_hits": None,
            "favicon": None
        }
        # heuristics whether to run http probe:
        banner_lower = (item["banner"] or "").lower()
        is_web_like = any(k in banner_lower for k in ("http","server","html","get /")) or port in KNOWN_ADMIN_PORTS_FLAT or port in (80,443,8080,8443,10000)
        if is_web_like:
            hits = http_probe_for_admin(ip, port, domain_host, timeout)
            item["http_hits"] = hits
            # try favicon
            for scheme in ("https","http"):
                try:
                    url = f"{scheme}://{ip}:{port}/favicon.ico"
                    r = requests.get(url, headers={"Host": domain_host}, timeout=3, verify=False)
                    if r.status_code == 200 and r.content:
                        item["favicon"] = sha256_bytes(r.content)
                        break
                except:
                    continue
        out_q.put(item)
    except Exception:
        return

# ----------------------------
# Orchestrator with live printing
# ----------------------------
def live_scan(ip, domain_host, ports_to_scan, workers, timeout):
    q = Queue()
    open_items = []
    total = len(ports_to_scan)
    scanned = 0
    lock = threading.Lock()
    print(f"\n🔗 Domain : {domain_host}")
    print(f"📍 IP     : {ip}")
    print(f"\n🔎 Scanning {total} ports with {workers} workers (timeout={timeout})...\n")

    def worker_wrapper(p):
        nonlocal scanned
        scan_port_worker(ip, p, timeout, domain_host, q)
        with lock:
            scanned += 1
            if scanned % 25 == 0 or scanned == total:
                # show progress every 25 ports or at end
                print(f"⏱ Progress: {scanned}/{total} ports scanned")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(worker_wrapper, p) for p in ports_to_scan]
        # while futures running, consume queue and print open ports live
        while True:
            done_count = sum(1 for f in futures if f.done())
            # print any queued open items
            while not q.empty():
                item = q.get()
                open_items.append(item)
                p = item["port"]
                # SAFE: use helper instead of splitlines()[0]
                banner = first_line_or_empty(item.get("banner", ""))
                banner = banner[:120]
                print(f"➤ Port {p}  OPEN | Banner: {banner or '(none)'}")
                # if http_hits present, print short summary immediately
                hits = item.get("http_hits")
                if hits:
                    for h in hits:
                        kws = h.get("keywords") or []
                        print(f"   → Possible admin URL: {h['url']}  (HTTP {h['status']})  keywords: {kws}")
            if done_count == len(futures):
                break
            time.sleep(0.05)

    # after all done, drain any last queue items
    while not q.empty():
        item = q.get()
        open_items.append(item)
        p = item["port"]
        banner = first_line_or_empty(item.get("banner", ""))
        banner = banner[:120]
        print(f"➤ Port {p}  OPEN | Banner: {banner or '(none)'}")
        hits = item.get("http_hits")
        if hits:
            for h in hits:
                kws = h.get("keywords") or []
                print(f"   → Possible admin URL: {h['url']}  (HTTP {h['status']})  keywords: {kws}")

    print(f"\n✅ Scan finished: {len(open_items)} open ports found.\n")
    return open_items

# ----------------------------
# Analyze & aggregate candidates
# ----------------------------
def aggregate_admin_candidates(open_items):
    candidates = []
    for it in open_items:
        p = it["port"]
        if it.get("http_hits"):
            for h in it["http_hits"]:
                candidates.append({
                    "port": p,
                    "url": h["url"],
                    "status": h["status"],
                    "title": h.get("title",""),
                    "keywords": h.get("keywords",[]),
                    "server_headers": h.get("server_headers",{})
                })
        else:
            # check banner for admin keywords
            b = (it.get("banner") or "").lower()
            if any(k in b for k in ADMIN_KEYWORDS):
                candidates.append({
                    "port": p,
                    "url": None,
                    "evidence": "banner",
                    "banner_snippet": (it.get("banner") or "")[:200]
                })
    return candidates

# ----------------------------
# Pretty final summary & optional open-in-browser
# ----------------------------
def final_report(domain_host, ip, open_items, candidates, no_browser, want_json):
    print("🔔 Final Summary\n" + "-"*40)
    print(f"Creator: Anish Kushwaha (🗣 ❤️‍🔥)")
    print(f"Target: {domain_host}  —  {ip}")
    print(f"Open ports: {len(open_items)}\n")
    for it in open_items:
        p = it["port"]
        b = first_line_or_empty(it.get("banner", ""))[:120]
        fh = it.get("favicon") or "-"
        print(f" • Port {p:<5} banner='{b}' favicon={fh}")

    if candidates:
        print("\n🔐 Possible admin/login panels found:")
        for c in candidates:
            if c.get("url"):
                print(f" ▶ {c['url']}  (port {c['port']})  status:{c['status']}  keywords:{c['keywords']}")
            else:
                print(f" ▶ Banner evidence on port {c['port']}: {c.get('banner_snippet','')[:100]}")
        # prompt to open each in browser (interactive)
        if not no_browser and sys.stdin.isatty():
            for c in candidates:
                if c.get("url"):
                    try:
                        ans = input(f"🌐 Open {c['url']} in browser? (y/n): ").strip().lower()
                    except EOFError:
                        ans = "n"
                    if ans == "y":
                        try:
                            webbrowser.open(c['url'])
                            print("🌍 Opening...")
                        except Exception as e:
                            print(f"⚠️ Failed to open: {e}")
    else:
        print("\n⚠️ No admin/login pages detected by heuristics.")

    if want_json:
        fn = f"{domain_host.replace('.','_')}_scan_results.json"
        out = {
            "creator": "Anish Kushwaha (🗣 ❤️‍🔥)",
            "target": {"domain": domain_host, "ip": ip},
            "open_ports": open_items,
            "candidates": candidates,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        try:
            with open(fn,"w",encoding="utf-8") as f:
                json.dump(out, f, indent=2, ensure_ascii=False)
            print(f"\n💾 Saved JSON -> {fn}")
        except Exception as e:
            print(f"❌ Failed to save JSON: {e}")

# ----------------------------
# Main CLI flow
# ----------------------------
def main():
    args = parse_args()
    if not args.url:
        try:
            args.url = input("Enter target URL or domain : ").strip()
        except EOFError:
            print("No URL provided. Exiting.")
            return

    domain_host, ip = resolve_domain(args.url)
    if not ip:
        print("❌ Could not resolve domain. Exiting.")
        return

    # build ports list: KNOWN_ADMIN first + 1..N
    n = int(args.ports)
    if n < 1:
        print("Ports must be >= 1")
        return
    if n > 65535:
        n = 65535
    ports = sorted(set(KNOWN_ADMIN_PORTS_FLAT + list(range(1, n+1))))

    workers = max(1, min(int(args.workers), MAX_WORKERS))
    timeout = max(0.01, float(args.timeout))

    # print header block like your old UI
    print("\nAnish — Security Scanner v2.3 ⚡☠️")
    print("Created by :-  𝔸ℕ𝕀𝕊ℍ 𝕂𝕌𝕊ℍ𝕎𝔸ℍ𝔸")
    print("Email :-  Anish_Kushwaha@proton.me")
    print("\n" + "*"*50 + "\n")

    open_items = live_scan(ip, domain_host, ports, workers, timeout)
    candidates = aggregate_admin_candidates(open_items)

    # If nothing found in prioritized scan, ask to run extended scan
    if not candidates:
        if sys.stdin.isatty():
            try:
                ans = input(f"No admin pages detected. Run extended top {DEFAULT_TOP_EXTENDED} port scan? (y/n): ").strip().lower()
            except EOFError:
                ans = "n"
        else:
            ans = "n"
        if ans == "y":
            ext = sorted(set(KNOWN_ADMIN_PORTS_FLAT + list(range(1, min(65535, DEFAULT_TOP_EXTENDED)+1))))
            print("\n➡ Running extended scan (top ports)...\n")
            open_items = live_scan(ip, domain_host, ext, workers, timeout)
            candidates = aggregate_admin_candidates(open_items)

    final_report(domain_host, ip, open_items, candidates, args.no_browser, args.json)
    print("\nScan completed. Be responsible. ✌️")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user.")
