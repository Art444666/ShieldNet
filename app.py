import os
from time import time
from collections import defaultdict, deque
from ipaddress import ip_address, ip_network
from flask import Flask, request, redirect, render_template, abort

app = Flask(__name__)

# === Конфигурация ===
CONFIG = {
    "protected_site_url": os.getenv("PROTECTED_SITE_URL", "https://example.com"),  # адрес защищаемого сайта
    "use_xff": os.getenv("USE_XFF", "1") == "1",  # учитывать X-Forwarded-For за прокси
    "company_name": os.getenv("COMPANY_NAME", "ShieldNet Security"),

    # Анти-флуд (IP)
    "ip_rate_limit": int(os.getenv("IP_RATE_LIMIT", "50")),         # макс запросов за окно
    "ip_rate_window_sec": int(os.getenv("IP_RATE_WINDOW", "10")),   # окно времени (сек)
    "ip_ban_sec": int(os.getenv("IP_BAN_SEC", "900")),              # бан IP (сек)

    # Анти-DDoS (диапазоны)
    "range_prefix": int(os.getenv("RANGE_PREFIX", "24")),                  # префикс /24
    "range_unique_ips_threshold": int(os.getenv("RANGE_UNIQUE", "30")),    # уникальных IP из префикса за окно
    "range_window_sec": int(os.getenv("RANGE_WINDOW", "10")),              # окно (сек)
    "range_ban_sec": int(os.getenv("RANGE_BAN_SEC", "1800")),              # бан диапазона (сек)

    # HyperGuard (злостные нарушители)
    "hyperguard_threshold": int(os.getenv("HYPERGUARD_THRESHOLD", "5")),   # после N банов → 400
    "hyperguard_ban_sec": int(os.getenv("HYPERGUARD_BAN_SEC", "86400")),   # длительность HG-бана (сек)

    # Маршрут страницы блокировки
    "block_page_route": os.getenv("BLOCK_ROUTE", "/blocked"),

    # Белый список
    "whitelist_ips": set(os.getenv("WHITELIST_IPS", "127.0.0.1").split(",")),
}

# === Хранилища (в памяти) ===
ip_requests = defaultdict(deque)             # IP -> deque[timestamps]
ip_bans = {}                                 # IP -> (until_ts, reason)
range_activity = defaultdict(lambda: {"ips": {}, "events": deque()})  # префикс -> активность
range_bans = {}                              # CIDR -> (until_ts, reason)
ip_violations = defaultdict(int)             # IP -> счётчик нарушений (банов)

def now():
    return time()

def get_client_ip():
    # Если стоит за прокси/балансировщиком — используем X-Forwarded-For
    if CONFIG["use_xff"]:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
    return (request.remote_addr or "").strip()

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
    if not info:
        return False
    until, _ = info
    if now() > until:
        ip_bans.pop(ip, None)
        return False
    return True

def is_banned_range(prefix):
    info = range_bans.get(prefix)
    if not info:
        return False
    until, _ = info
    if now() > until:
        range_bans.pop(prefix, None)
        return False
    return True

def ban_ip(ip, seconds, reason):
    ip_bans[ip] = (now() + seconds, reason)
    ip_violations[ip] += 1
    # Перевод в HyperGuard при превышении порога
    if ip_violations[ip] >= CONFIG["hyperguard_threshold"]:
        ip_bans[ip] = (now() + CONFIG["hyperguard_ban_sec"], "HyperGuard")
        # Лог можно заменить на нормальный логгер
        print(f"[HyperGuard] {ip} переведён в HyperGuard на {CONFIG['hyperguard_ban_sec']}s")

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
    for k in stale:
        act["ips"].pop(k, None)
    return prefix, len(act["ips"])

def should_ban_range(prefix, unique_ips_count):
    return unique_ips_count >= CONFIG["range_unique_ips_threshold"]

def block_redirect(reason, ip):
    # Редирект на страницу блокировки
    return redirect(f"{CONFIG['block_page_route']}?ip={ip}&reason={reason}", code=302)

@app.before_request
def guard():
    ip = get_client_ip() or "unknown"

    # Белый список → сразу пропускаем на защищаемый сайт
    if ip in CONFIG["whitelist_ips"]:
        return redirect(CONFIG["protected_site_url"])

    # HyperGuard: все запросы от злостных нарушителей → 400
    if ip_violations[ip] >= CONFIG["hyperguard_threshold"]:
        abort(400)

    # Проверка банов (IP/диапазон)
    prefix = ip_to_prefix(ip, CONFIG["range_prefix"])
    if is_banned_ip(ip):
        # Если причина HyperGuard — сразу 400
        _, reason = ip_bans.get(ip, (0, ""))
        if reason == "HyperGuard":
            abort(400)
        return block_redirect("Слишком частые запросы", ip)
    if is_banned_range(prefix):
        return block_redirect("Подозрение на DDoS из диапазона", ip)

    # Учёт активности
    record_ip_request(ip)
    pfx, unique_ips = record_range_activity(ip)

    # Локальный анти-флуд (IP)
    if exceeded_ip_rate(ip):
        ban_ip(ip, CONFIG["ip_ban_sec"], "Слишком частые запросы")
        return block_redirect("Слишком частые запросы", ip)

    # Диапазонный анти-DDoS
    if should_ban_range(pfx, unique_ips):
        ban_range(pfx, CONFIG["range_ban_sec"], "Подозрение на DDoS из диапазона")
        return block_redirect("Подозрение на DDoS из диапазона", ip)

    # Обычные пользователи → перенаправляем на защищаемый сайт
    return redirect(CONFIG["protected_site_url"])

@app.route(CONFIG["block_page_route"])
def blocked():
    ip = request.args.get("ip", "Unknown")
    reason = request.args.get("reason", "Доступ ограничен")
    return render_template("blocked.html",
                           company=CONFIG["company_name"],
                           ip=ip,
                           reason=reason), 403

# Админ-эндпоинты (минимум)
@app.route("/_admin/unban/ip/<ip>", methods=["POST"])
def unban_ip(ip):
    ip_bans.pop(ip, None)
    ip_violations[ip] = 0
    return {"status": "ok", "message": f"Unbanned {ip}"}

@app.route("/_admin/unban/range/<path:cidr>", methods=["POST"])
def unban_range(cidr):
    range_bans.pop(cidr, None)
    return {"status": "ok", "message": f"Unbanned range {cidr}"}

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
