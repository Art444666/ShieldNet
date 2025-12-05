import time
from collections import deque
from flask import Flask, request, abort

app = Flask(__name__)

CONFIG = {
    "protected_site_url": "https://santa-secret.ru/box/Santa20257klass/card",   # адрес твоего сайта
    "company_name": "ShieldNet Security",
    "block_page_file": "blocked.html",

    "global_rate_limit": 90,    # запросов в секунду
    "coma_duration": 20,        # длительность "комы" (сек)
    "coma_max_count": 5,        # сколько раз подряд можно упасть в кому
    "coma_ban_duration": 20,   # глобальный бан (сек) = 5 минут
}

# === Глобальные состояния ===
global_requests = deque()
coma_until = 0
coma_count = 0
ban_until = 0

def now(): return time.time()

def record_global_request():
    ts = now()
    global_requests.append(ts)
    # чистим старые записи (оставляем только за последнюю секунду)
    while global_requests and ts - global_requests[0] > 1:
        global_requests.popleft()

def exceeded_global_rate():
    return len(global_requests) > CONFIG["global_rate_limit"]

def render_block_page(reason="Сервис перегружен"):
    with open(CONFIG["block_page_file"], encoding="utf-8") as f:
        html = f.read()
    html = html.replace("{{ company }}", CONFIG["company_name"])
    html = html.replace("{{ ip }}", request.remote_addr or "unknown")
    html = html.replace("{{ reason }}", reason)
    return html, 403

@app.before_request
def guard():
    global coma_until, coma_count, ban_until

    # Записываем глобальный запрос
    record_global_request()

    # Проверка глобального бана
    if now() < ban_until:
        abort(400)

    # Проверка режима "кома"
    if now() < coma_until:
        return render_block_page("Сервис временно недоступен (защита)")

    # Если превышен глобальный лимит
    if exceeded_global_rate():
        coma_until = now() + CONFIG["coma_duration"]
        coma_count += 1
        if coma_count >= CONFIG["coma_max_count"]:
            ban_until = now() + CONFIG["coma_ban_duration"]
            coma_count = 0  # сброс после бана
        return render_block_page("Сервис временно недоступен (защита)")

    # ✅ Обычные пользователи → редирект на сайт
    return f'<meta http-equiv="refresh" content="0;url={CONFIG["protected_site_url"]}">'

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
