import os
from time import time
from collections import defaultdict, deque
from ipaddress import ip_address, ip_network
from flask import Flask, request, redirect, abort

app = Flask(__name__)

# === Конфигурация ===
CONFIG = {
    "protected_site_url": os.getenv("PROTECTED_SITE_URL", "https://santa-secret.ru/box/Santa20257klass/card"),
    "company_name": os.getenv("COMPANY_NAME", "ShieldNet Security"),
    "block_page_file": os.getenv("BLOCK_PAGE_FILE", "index.html"),

    "ip_rate_limit": 50,
    "ip_rate_window_sec": 10,
    "ip_ban_sec": 900,

    "range_prefix": 24,
    "range_unique_ips_threshold": 30,
    "range_window_sec": 10,
    "range_ban_sec": 100,

    "hyperguard_threshold": 5,
    "hyperguard_ban_sec": 900,

    "whitelist_ips": {"127.0.0.1"},
}

# === Хранилища ===
ip_requests = defaultdict(deque)
ip_bans = {}
range_activity = defaultdict(lambda: {"ips": {}, "events": deque()})
range_bans = {}
ip_violations = defaultdict(int)

def now(): return time()

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()

def ip_to_prefix(ip_str, prefix_len):
    ip = ip_address(ip_str)
    net = ip_network(f"{ip}/{prefix_len}", strict=False)
    return str(net)

def prune_deque(dq, window_sec):
    t = now()
    while dq and (t - dq[0]) > window_sec:
        dq.popleft()

def is_banned_ip(ip):
    info = ip_bans.get(ip)
    if not info: return False
    until, _ = info
    if now() > until:
        ip_bans.pop(ip, None)
        return False
    return True

def is_banned_range(prefix):
    info = range_bans.get(prefix)
    if not info: return False
    until, _ = info
    if now() > until:
        range_bans.pop(prefix, None)
        return False
    return True

def ban_ip(ip, seconds, reason):
    ip_bans[ip] = (now() + seconds, reason)
    ip_violations[ip] += 1
    if ip_violations[ip] >= CONFIG["hyperguard_threshold"]:
        ip_bans[ip] = (now() + CONFIG["hyperguard_ban_sec"], "HyperGuard")

def ban_range(prefix, seconds, reason):
    range_bans[prefix] = (now() + seconds, reason)

def record_ip_request(ip):
    dq = ip_requests[ip]
    dq.append(now())
    prune_deque(dq, CONFIG["ip_rate_window_sec"])

def exceeded_ip_rate(ip):
    dq = ip_requests[ip]
    return len(dq) > CONFIG["ip_rate_limit"]

def record_range_activity(ip):
    prefix = ip_to_prefix(ip, CONFIG["range_prefix"])
    act = range_activity[prefix]
    ts = now()
    act["ips"][ip] = ts
    act["events"].append(ts)
    prune_deque(act["events"], CONFIG["range_window_sec"])
    cutoff = ts - CONFIG["range_window_sec"]
    stale = [k for k, t in act["ips"].items() if t < cutoff]
    for k in stale: act["ips"].pop(k, None)
    return prefix, len(act["ips"])

def should_ban_range(prefix, unique_ips_count):
    return unique_ips_count >= CONFIG["range_unique_ips_threshold"]

def render_block_page(ip, reason):
    # Загружаем blocked.html из той же папки
    with open(CONFIG["block_page_file"], encoding="utf-8") as f:
        html = f.read()
    # Подставляем значения вручную
    html = html.replace("{{ company }}", CONFIG["company_name"])
    html = html.replace("{{ ip }}", ip)
    html = html.replace("{{ reason }}", reason)
    return html, 403

@app.before_request
def guard():
    ip = get_client_ip()

    if ip in CONFIG["whitelist_ips"]:
        return redirect(CONFIG["protected_site_url"])

    if ip_violations[ip] >= CONFIG["hyperguard_threshold"]:
        abort(400)

    prefix = ip_to_prefix(ip, CONFIG["range_prefix"])
    if is_banned_ip(ip):
        _, reason = ip_bans.get(ip, (0, ""))
        if reason == "HyperGuard":
            abort(400)
        return render_block_page(ip, "Слишком частые запросы")
    if is_banned_range(prefix):
        return render_block_page(ip, "Подозрение на DDoS из диапазона")

    record_ip_request(ip)
    pfx, unique_ips = record_range_activity(ip)

    if exceeded_ip_rate(ip):
        ban_ip(ip, CONFIG["ip_ban_sec"], "Слишком частые запросы")
        return render_block_page(ip, "Слишком частые запросы")

    if should_ban_range(pfx, unique_ips):
        ban_range(pfx, CONFIG["range_ban_sec"], "Подозрение на DDoS из диапазона")
        return render_block_page(ip, "Подозрение на DDoS из диапазона")

    return redirect(CONFIG["protected_site_url"])

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
