"""
BeamLDrive — сервер поддержки: Telegram-бот + API для лаунчера.
Данные хранятся в Supabase (PostgreSQL).

Переменные окружения (или support_config.json):
  BOT_TOKEN, ADMIN_ID, SUPABASE_URL, SUPABASE_KEY (секретный ключ sb_secret_… или service_role), PORT
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
CFG_FILE = BASE / "support_config.json"
try:
    CFG = json.loads(CFG_FILE.read_text(encoding="utf-8"))
except Exception:
    CFG = {}

TOKEN = os.environ.get("BOT_TOKEN") or CFG.get("token", "")
ADMIN = int(os.environ.get("ADMIN_ID") or CFG.get("admin_id") or 0)
PORT = int(os.environ.get("PORT") or os.environ.get("SUPPORT_PORT") or CFG.get("port") or 8787)
SB_URL = (os.environ.get("SUPABASE_URL") or CFG.get("supabase_url", "")).rstrip("/")
SB_KEY = os.environ.get("SUPABASE_KEY") or CFG.get("supabase_key", "")
TILDA_KEY = os.environ.get("TILDA_KEY") or CFG.get("tilda_key", "")  # секрет для вебхука сайта
OFFLINE = bool(os.environ.get("SUPPORT_OFFLINE"))  # только для тестов
API = f"https://api.telegram.org/bot{TOKEN}/"

ROLES = ("base", "zero", "moderator", "smm", "admin")
# Роли = готовые наборы прав. Права можно добавлять/убирать командами бота.
PRESETS = {
    "base": "vg,mp",
    "zero": "vg,mp,bng,server",
    "moderator": "vg,mp,mod",              # модератор: отвечает игрокам, банит на время
    "smm": "vg,mp,bng,tg,mod",             # директор СММ: как модератор + каталоги и канал
    "admin": "vg,mp,bng,server,tg,mod",    # разработчик: всё
}
STAFF_ROLES = ("moderator", "smm", "admin")
FOREVER = 9999999999
MAX_STAFF_BAN_MIN = 10080  # 7 дней — максимум для модераторов

# Нецензурная лексика: корни слов (ё приводится к е). Фильтр базовый — возможны ложные срабатывания.
PROFANE_ROOTS = ("хуй", "хуе", "хуя", "пизд", "ебл", "ебан", "ебат", "ебу", "ебн", "блят", "бляд",
                 "мудак", "мудил", "гандон", "залуп", "шлюх", "сука", "суки", "сучк", "сучар",
                 "пидор", "пидар", "дроч", "еблан")


def die(msg):
    print("\n[ОШИБКА] " + msg, flush=True)
    if sys.stdin and sys.stdin.isatty():
        try:
            input("\nНажмите Enter, чтобы закрыть окно...")
        except Exception:
            pass
    sys.exit(1)


if not OFFLINE:
    if not TOKEN or "ABC" in TOKEN:
        die("Не задан BOT_TOKEN (или token в support_config.json).")
    if not SB_URL or not SB_KEY:
        die("Не заданы SUPABASE_URL и SUPABASE_KEY (адрес и секретный ключ проекта Supabase).")


# ───────────────────────── Telegram ─────────────────────────
def call(method, **params):
    if OFFLINE:
        return {"ok": False, "description": "offline"}
    req = urllib.request.Request(
        API + method, data=json.dumps(params).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=70) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"ok": False, "description": str(e)}
    except Exception as e:
        return {"ok": False, "description": str(e)}


# ───────────────────────── Supabase (REST) ─────────────────────────
def rest(method, table, query="", body=None, prefer=None):
    url = f"{SB_URL}/rest/v1/{table}" + (f"?{query}" if query else "")
    headers = {"apikey": SB_KEY, "Content-Type": "application/json"}
    if SB_KEY.startswith("eyJ"):  # старые JWT-ключи дублируем в Authorization; sb_secret_… — нет
        headers["Authorization"] = f"Bearer {SB_KEY}"
    if prefer:
        headers["Prefer"] = prefer
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw.strip() else []
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Supabase {e.code}: {e.read().decode()[:300]}")


def q(v):
    return urllib.parse.quote(str(v), safe="")


_db_lock = threading.Lock()


# ───────────────────────── Пользователи ─────────────────────────
def user_by_id(uid):
    rows = rest("GET", "users", f"id=eq.{int(uid)}&select=*")
    return rows[0] if rows else None


def user_by_name(name):
    rows = rest("GET", "users", f"uname=eq.{q(name.lower())}&select=*")
    return rows[0] if rows else None


def create_user(username, salt, pw, contact):
    try:
        with _db_lock:
            rows = rest("POST", "users", body={
                "uname": username.lower(), "username": username, "salt": salt, "pw": pw,
                "contact": contact, "created": int(time.time()),
                "role": "base", "perms": PRESETS["base"], "banned_until": 0, "ban_reason": "",
                "email": contact.lower() if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", contact or "") else "",
                "tg_chat": 0},
                prefer="return=representation")
        return rows[0]
    except RuntimeError as e:
        if "409" in str(e) or "duplicate" in str(e).lower():
            return None
        raise


def new_session(uid):
    t = secrets.token_urlsafe(32)
    with _db_lock:
        rest("POST", "sessions", body={"token": t, "user_id": uid, "created": int(time.time())},
             prefer="return=minimal")
    return t


def user_by_token(tok):
    rows = rest("GET", "sessions", f"token=eq.{q(tok)}&select=user_id")
    if not rows:
        return None
    return user_by_id(rows[0]["user_id"])


def hash_pw(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 120_000).hex()


def user_perms(u):
    return {x for x in (u.get("perms") or "").split(",") if x}


def can_moderate(u):
    return "mod" in user_perms(u)


def mask_email(e):
    if not e or "@" not in e:
        return ""
    name, dom = e.split("@", 1)
    return name[:2] + "***@" + dom


def user_view(u):
    return {"username": u["username"], "role": u.get("role") or "base",
            "perms": sorted(user_perms(u)), "contact": u.get("contact") or "",
            "banned_until": int(u.get("banned_until") or 0), "ban_reason": u.get("ban_reason") or "",
            "email": mask_email(u.get("email") or ""), "tg": bool(u.get("tg_chat"))}


def ban_info(u):
    until = int(u.get("banned_until") or 0)
    if until > int(time.time()):
        return {"banned_until": until, "ban_reason": u.get("ban_reason") or ""}
    return None


def apply_ban(target, minutes, reason):
    """minutes: >0 — на столько минут, 0 — снять бан, -1 — навсегда."""
    now = int(time.time())
    until = 0 if minutes == 0 else (FOREVER if minutes < 0 else now + minutes * 60)
    with _db_lock:
        rest("PATCH", "users", f"id=eq.{int(target['id'])}",
             body={"banned_until": until, "ban_reason": "" if minutes == 0 else reason[:200]},
             prefer="return=minimal")
    return until


# ───────────────────────── Тикеты и сообщения ─────────────────────────
def is_profane(text):
    norm = (text or "").lower().replace("ё", "е")
    for w in re.findall(r"[a-zа-я]+", norm):
        if any(w.startswith(r.replace("ё", "е")) for r in PROFANE_ROOTS):
            return True
    return False


def ticket_for_user(user, tid):
    try:
        tid = int(tid)
    except (TypeError, ValueError):
        return None
    rows = rest("GET", "tickets", f"id=eq.{tid}&user_id=eq.{int(user['id'])}&select=*")
    return rows[0] if rows else None


def add_message(tid, sender, text, seen):
    with _db_lock:
        rest("POST", "messages", body={"ticket_id": tid, "sender": sender, "text": text[:2000],
                                       "created": int(time.time()), "seen": seen},
             prefer="return=minimal")


def touch_ticket(tid, **extra):
    fields = {"updated": int(time.time()), **extra}
    with _db_lock:
        rest("PATCH", "tickets", f"id=eq.{int(tid)}", body=fields, prefer="return=minimal")


def set_map(msg_id, kind, ref):
    with _db_lock:
        rest("POST", "tg_map", body={"msg_id": msg_id, "kind": kind, "ref": ref},
             prefer="resolution=merge-duplicates,return=minimal")


def get_map(msg_id):
    rows = rest("GET", "tg_map", f"msg_id=eq.{int(msg_id)}&select=kind,ref")
    return rows[0] if rows else None


def tg_notify(text, kind, ref):
    if not ADMIN:
        return
    r = call("sendMessage", chat_id=ADMIN, text=text[:4000])
    if r.get("ok"):
        set_map(r["result"]["message_id"], kind, ref)


def reply_ticket(tid, text):
    if not text:
        return "В тикет можно отвечать только текстом."
    if not rest("GET", "tickets", f"id=eq.{int(tid)}&select=id"):
        return f"Тикет #{tid} не найден."
    add_message(tid, "admin", text, 0)
    touch_ticket(tid)
    return f"✅ Ответ отправлен в тикет #{tid}"


# ───────────────────────── Лимиты ─────────────────────────
_rate = {}


def rate_ok(key, limit, per):
    now = time.time()
    arr = [t for t in _rate.get(key, []) if now - t < per]
    if len(arr) >= limit:
        _rate[key] = arr
        return False
    arr.append(now)
    _rate[key] = arr
    return True


# ───────────────────────── API лаунчера ─────────────────────────
def api_register(d, ip):
    u, p = str(d.get("username", "")).strip(), str(d.get("password", ""))
    contact = str(d.get("contact", "")).strip()[:80]
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{3,24}", u):
        return 400, {"error": "Имя: 3–24 символа, латиница, цифры, _ . -"}
    if len(p) < 6 or len(p) > 100:
        return 400, {"error": "Пароль должен быть не короче 6 символов"}
    if not rate_ok("reg:" + ip, 5, 3600):
        return 429, {"error": "Слишком много регистраций, попробуйте позже"}
    salt = secrets.token_hex(16)
    created = create_user(u, salt, hash_pw(p, salt), contact)
    if not created:
        return 409, {"error": "Такое имя уже занято"}
    return 200, {"token": new_session(created["id"]), "username": u}


def api_login(d, ip):
    u, p = str(d.get("username", "")).strip(), str(d.get("password", ""))
    if not rate_ok("login:" + ip, 15, 600):
        return 429, {"error": "Слишком много попыток, подождите несколько минут"}
    row = user_by_name(u)
    if not row or not hmac.compare_digest(row["pw"], hash_pw(p, row["salt"])):
        return 401, {"error": "Неверное имя или пароль"}
    return 200, {"token": new_session(row["id"]), "username": row["username"]}


def api_me(user, d):
    return 200, user_view(user)


def api_change_password(user, d):
    old, new = str(d.get("old", "")), str(d.get("new", ""))
    if len(new) < 6 or len(new) > 100:
        return 400, {"error": "Новый пароль: от 6 символов"}
    if not hmac.compare_digest(user["pw"], hash_pw(old, user["salt"])):
        return 403, {"error": "Старый пароль неверный"}
    salt = secrets.token_hex(16)
    with _db_lock:
        rest("PATCH", "users", f"id=eq.{int(user['id'])}",
             body={"salt": salt, "pw": hash_pw(new, salt)}, prefer="return=minimal")
    return 200, {"ok": True}


def api_tilda(query, raw, ctype, ip):
    """Вебхук формы с сайта Tilda. Только уведомляет админа — роли не выдаёт."""
    key = urllib.parse.parse_qs(query).get("key", [""])[0]
    if not TILDA_KEY or not hmac.compare_digest(key, TILDA_KEY):
        return 403, {"error": "forbidden"}
    if not rate_ok("tilda:" + ip, 30, 3600):
        return 429, {"error": "too many"}
    if "json" in ctype:
        data = json.loads(raw or b"{}")
    else:
        data = {k: v[0] for k, v in urllib.parse.parse_qs(raw.decode("utf-8", "replace"),
                                                         keep_blank_values=True).items()}
    data = {str(k).strip().lower(): v for k, v in data.items()}  # Tilda шлёт «Name», «Email», «Phone»
    name = str(data.get("name") or "").strip()[:60]
    contact = str(data.get("email") or data.get("phone") or data.get("contact") or "").strip()[:80]
    if not name:
        return 400, {"error": "no name"}
    if ADMIN:
        call("sendMessage", chat_id=ADMIN, text=(
            f"🌐 Заявка с сайта\nИмя: {name}\nКонтакт: {contact or '—'}\n\n"
            f"Если это аккаунт в лаунчере, выдайте роль:\n/role {name} moderator  (или smm)"))
    return 200, {"ok": True}


def api_news_public():
    rows = rest("GET", "news_posts", "order=id.desc&limit=20&select=id,text,created")
    out = []
    for r in rows:
        m = re.search(r"https?://\S+", r["text"])
        out.append({"id": r["id"], "text": r["text"], "created": r["created"],
                    "link": m.group(0) if m else ""})
    return {"news": out}


def api_forum_public():
    rows = rest("GET", "forum_posts", "order=id.desc&limit=50&select=id,username,text,created")
    return {"posts": rows}


def api_forum_post(user, d):
    text = str(d.get("text", "")).strip()[:1000]
    if len(text) < 2:
        return 400, {"error": "Напишите сообщение"}
    if is_profane(text):
        return 400, {"error": "В сообщении есть нецензурные слова. Уберите их и отправьте снова."}
    if not rate_ok("forum:%d" % user["id"], 10, 600):
        return 429, {"error": "Слишком часто, подождите немного"}
    with _db_lock:
        rest("POST", "forum_posts", body={"username": user["username"], "text": text,
                                          "created": int(time.time())}, prefer="return=minimal")
    if ADMIN:
        call("sendMessage", chat_id=ADMIN, text=f"💬 Форум · {user['username']}\n{text}")
    return 200, {"ok": True}


CODE_TTL = 600
PURPOSES = ("password", "email")


def smtp_send(to, subject, body):
    import smtplib
    from email.message import EmailMessage
    host = os.environ.get("SMTP_HOST", "")
    user = os.environ.get("SMTP_USER", "")
    sender = os.environ.get("SMTP_FROM") or user
    if not host or not sender:
        raise RuntimeError("почта на сервере не настроена")
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, sender, to
    msg.set_content(body)
    with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT") or 587), timeout=20) as smtp:
        smtp.starttls()
        smtp.login(user, os.environ.get("SMTP_PASS", ""))
        smtp.send_message(msg)


def make_code(user_id, purpose, extra=""):
    code = f"{secrets.randbelow(10 ** 6):06d}"
    with _db_lock:
        rest("DELETE", "account_codes", f"user_id=eq.{int(user_id)}&purpose=eq.{q(purpose)}",
             prefer="return=minimal")
        rest("POST", "account_codes", body={
            "user_id": user_id, "purpose": purpose, "extra": extra,
            "code_hash": hashlib.sha256(code.encode()).hexdigest(),
            "expires": int(time.time()) + CODE_TTL, "attempts": 0}, prefer="return=minimal")
    return code


def api_tg_link(user, d):
    code = make_code(user["id"], "tglink")
    return 200, {"code": code}


def api_code_request(user, d):
    purpose = str(d.get("purpose", ""))
    if purpose not in PURPOSES:
        return 400, {"error": "Неверный запрос"}
    if not rate_ok("acc:%d" % user["id"], 6, 3600):
        return 429, {"error": "Слишком много запросов кода, подождите час"}
    extra = ""
    if purpose == "email":
        extra = str(d.get("new_email", "")).strip().lower()[:120]
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", extra):
            return 400, {"error": "Введите корректную новую почту"}
    code = make_code(user["id"], purpose, extra)
    what = "смены пароля" if purpose == "password" else "привязки новой почты"
    text = f"Код для {what}: {code}\nДействует 10 минут. Если это были не вы — просто проигнорируйте."
    if user.get("email") and purpose == "email":  # пароль меняем только через Telegram
        try:
            smtp_send(user["email"], "BeamLDrive: код подтверждения", text)
        except Exception as e:
            return 502, {"error": f"Не удалось отправить письмо: {e}"}
        return 200, {"channel": "почта", "to": mask_email(user["email"])}
    if user.get("tg_chat"):
        r = call("sendMessage", chat_id=int(user["tg_chat"]), text=text)
        if not r.get("ok"):
            return 502, {"error": "Не удалось отправить код в Telegram"}
        return 200, {"channel": "Telegram"}
    if purpose == "password":
        return 400, {"error": "Для смены пароля привяжите Telegram (кнопка «Привязать Telegram»)"}
    return 400, {"error": "Сначала привяжите Telegram, чтобы получить код"}


def api_code_confirm(user, d):
    purpose = str(d.get("purpose", ""))
    if purpose not in PURPOSES:
        return 400, {"error": "Неверный запрос"}
    rows = rest("GET", "account_codes", f"user_id=eq.{int(user['id'])}&purpose=eq.{q(purpose)}&select=*")
    if not rows:
        return 400, {"error": "Сначала запросите код"}
    row = rows[0]
    if int(row["expires"]) < int(time.time()):
        rest("DELETE", "account_codes", f"user_id=eq.{int(user['id'])}&purpose=eq.{q(purpose)}",
             prefer="return=minimal")
        return 400, {"error": "Код истёк, запросите новый"}
    if int(row["attempts"]) >= 5:
        return 400, {"error": "Слишком много неверных попыток, запросите новый код"}
    code = str(d.get("code", "")).strip()
    if not hmac.compare_digest(row["code_hash"], hashlib.sha256(code.encode()).hexdigest()):
        with _db_lock:
            rest("PATCH", "account_codes", f"user_id=eq.{int(user['id'])}&purpose=eq.{q(purpose)}",
                 body={"attempts": int(row["attempts"]) + 1}, prefer="return=minimal")
        return 400, {"error": "Неверный код"}
    if purpose == "password":
        new = str(d.get("new_password", ""))
        if len(new) < 6 or len(new) > 100:
            return 400, {"error": "Новый пароль: от 6 символов"}
        salt = secrets.token_hex(16)
        with _db_lock:
            rest("PATCH", "users", f"id=eq.{int(user['id'])}",
                 body={"salt": salt, "pw": hash_pw(new, salt)}, prefer="return=minimal")
    else:
        with _db_lock:
            rest("PATCH", "users", f"id=eq.{int(user['id'])}", body={"email": row["extra"]},
                 prefer="return=minimal")
    with _db_lock:
        rest("DELETE", "account_codes", f"user_id=eq.{int(user['id'])}&purpose=eq.{q(purpose)}",
             prefer="return=minimal")
    return 200, {"ok": True}


def api_list(user, d):
    rows = rest("GET", "tickets", f"user_id=eq.{int(user['id'])}&order=updated.desc&limit=100"
                                  f"&select=id,subject,status,updated")
    unread = {}
    ids = [r["id"] for r in rows]
    if ids:
        msgs = rest("GET", "messages", f"ticket_id=in.({','.join(str(i) for i in ids)})"
                                       f"&sender=eq.admin&seen=eq.0&select=ticket_id")
        for m in msgs:
            unread[m["ticket_id"]] = unread.get(m["ticket_id"], 0) + 1
    out = [{"id": r["id"], "subject": r["subject"], "status": r["status"], "updated": r["updated"],
            "unread": unread.get(r["id"], 0)} for r in rows]
    return 200, {"tickets": out}


def api_messages(user, d):
    t = ticket_for_user(user, d.get("ticket_id"))
    if not t:
        return 404, {"error": "Тикет не найден"}
    msgs = rest("GET", "messages", f"ticket_id=eq.{int(t['id'])}&order=id.asc&select=sender,text,created")
    with _db_lock:
        rest("PATCH", "messages", f"ticket_id=eq.{int(t['id'])}&sender=eq.admin&seen=eq.0",
             body={"seen": 1}, prefer="return=minimal")
    return 200, {"ticket": t, "messages": msgs}


def api_create(user, d):
    subject = str(d.get("subject", "")).strip()[:80] or "Без темы"
    text = str(d.get("text", "")).strip()[:2000]
    if len(text) < 3:
        return 400, {"error": "Опишите проблему подробнее"}
    if is_profane(text) or is_profane(subject):
        return 400, {"error": "В обращении есть нецензурные слова. Уберите их и отправьте снова."}
    if not rate_ok("tk:%d" % user["id"], 3, 300):
        return 429, {"error": "Слишком часто. Подождите пару минут"}
    now = int(time.time())
    with _db_lock:
        rows = rest("POST", "tickets", body={"user_id": user["id"], "subject": subject, "status": "open",
                                             "created": now, "updated": now}, prefer="return=representation")
    tid = rows[0]["id"]
    add_message(tid, "user", text, 1)
    tg_notify(f"🎫 Тикет #{tid} · {subject}\nОт: {user['username']} · контакт: {user.get('contact') or '—'}\n\n{text}",
              "ticket", tid)
    return 200, {"ticket_id": tid}


def api_send(user, d):
    text = str(d.get("text", "")).strip()[:2000]
    if not text:
        return 400, {"error": "Пустое сообщение"}
    if is_profane(text):
        return 400, {"error": "В сообщении есть нецензурные слова. Уберите их и отправьте снова."}
    if not rate_ok("msg:%d" % user["id"], 12, 60):
        return 429, {"error": "Слишком часто"}
    t = ticket_for_user(user, d.get("ticket_id"))
    if not t:
        return 404, {"error": "Тикет не найден"}
    add_message(t["id"], "user", text, 1)
    touch_ticket(t["id"], status="open")
    tg_notify(f"💬 Тикет #{t['id']} · {t['subject']}\n{user['username']}:\n{text}", "ticket", t["id"])
    return 200, {"ok": True}


# ───── модерация (модераторы, директор СММ, разработчик) ─────
def api_staff_tickets(user, d):
    if not can_moderate(user):
        return 403, {"error": "Нет доступа"}
    now = int(time.time())
    rows = rest("GET", "tickets", "status=eq.open&order=updated.desc&limit=100&select=id,subject,user_id,updated")
    owners = {}
    if rows:
        ids = ",".join(str(r["user_id"]) for r in rows)
        for u in rest("GET", "users", f"id=in.({ids})&select=id,username,banned_until"):
            owners[u["id"]] = u
    out = []
    for r in rows:
        o = owners.get(r["user_id"], {})
        out.append({"id": r["id"], "subject": r["subject"], "updated": r["updated"],
                    "username": o.get("username", "?"),
                    "banned": int(o.get("banned_until") or 0) > now})
    return 200, {"tickets": out}


def api_staff_messages(user, d):
    if not can_moderate(user):
        return 403, {"error": "Нет доступа"}
    try:
        tid = int(d.get("ticket_id"))
    except (TypeError, ValueError):
        return 400, {"error": "Нет тикета"}
    rows = rest("GET", "tickets", f"id=eq.{tid}&select=*")
    if not rows:
        return 404, {"error": "Тикет не найден"}
    owner = user_by_id(rows[0]["user_id"]) or {}
    msgs = rest("GET", "messages", f"ticket_id=eq.{tid}&order=id.asc&select=sender,text,created")
    return 200, {"ticket": rows[0], "username": owner.get("username", "?"), "messages": msgs}


def api_staff_reply(user, d):
    if not can_moderate(user):
        return 403, {"error": "Нет доступа"}
    text = str(d.get("text", "")).strip()[:2000]
    if not text:
        return 400, {"error": "Пустой ответ"}
    try:
        tid = int(d.get("ticket_id"))
    except (TypeError, ValueError):
        return 400, {"error": "Нет тикета"}
    if not rest("GET", "tickets", f"id=eq.{tid}&select=id"):
        return 404, {"error": "Тикет не найден"}
    add_message(tid, "admin", text, 0)   # игрок видит ответ как «Поддержка»
    touch_ticket(tid)
    return 200, {"ok": True}


def api_staff_ban(user, d):
    if not can_moderate(user):
        return 403, {"error": "Нет доступа"}
    target = user_by_name(str(d.get("username", "")))
    if not target:
        return 404, {"error": "Пользователь не найден"}
    if target["id"] == user["id"]:
        return 400, {"error": "Нельзя банить самого себя"}
    is_admin = user.get("role") == "admin"
    if (target.get("role") or "base") in STAFF_ROLES and not is_admin:
        return 403, {"error": "Сотрудников банит только разработчик"}
    try:
        minutes = int(d.get("minutes", 0))
    except (TypeError, ValueError):
        return 400, {"error": "Неверный срок"}
    if minutes < 0 and not is_admin:
        return 403, {"error": "Бан навсегда доступен только разработчику"}
    if minutes > MAX_STAFF_BAN_MIN and not is_admin:
        return 400, {"error": "Модератор может банить максимум на 7 дней"}
    until = apply_ban(target, minutes, str(d.get("reason", "")))
    return 200, {"ok": True, "banned_until": until}


ROUTES_AUTH = {
    "/api/me": api_me, "/api/account/password": api_change_password,
    "/api/tickets/list": api_list, "/api/tickets/messages": api_messages,
    "/api/tickets/create": api_create, "/api/tickets/send": api_send,
    "/api/staff/tickets": api_staff_tickets, "/api/staff/messages": api_staff_messages,
    "/api/staff/reply": api_staff_reply, "/api/staff/ban": api_staff_ban,
    "/api/forum/post": api_forum_post,
    "/api/account/tglink": api_tg_link, "/api/account/code": api_code_request,
    "/api/account/confirm": api_code_confirm,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "BeamLDriveSupport"

    def log_message(self, *a):
        pass

    def _reply(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/ping":
            return self._reply(200, {"ok": True})
        if self.path.split("?")[0] == "/api/forum":
            try:
                return self._reply(200, api_forum_public())
            except Exception as e:
                print("forum error:", e, flush=True)
                return self._reply(500, {"error": "Ошибка сервера"})
        if self.path.split("?")[0] == "/api/news":
            try:
                return self._reply(200, api_news_public())
            except Exception as e:
                print("news error:", e, flush=True)
                return self._reply(500, {"error": "Ошибка сервера"})
        self._reply(404, {"error": "not found"})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > 20000:
                return self._reply(413, {"error": "too large"})
            raw = self.rfile.read(n)
            ip = (self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                  or self.client_address[0])
            url = urllib.parse.urlparse(self.path)
            if url.path == "/api/tilda":
                return self._reply(*api_tilda(url.query, raw, self.headers.get("Content-Type", ""), ip))
            d = json.loads(raw or b"{}")
            if self.path == "/api/register":
                return self._reply(*api_register(d, ip))
            if self.path == "/api/login":
                return self._reply(*api_login(d, ip))
            fn = ROUTES_AUTH.get(self.path)
            if not fn:
                return self._reply(404, {"error": "not found"})
            user = user_by_token(d.get("token"))
            if not user:
                return self._reply(401, {"error": "Нужно войти заново"})
            if fn is not api_me:  # в бане всё закрыто, кроме проверки статуса аккаунта
                b = ban_info(user)
                if b:
                    return self._reply(403, {"error": "Аккаунт заблокирован", **b})
            return self._reply(*fn(user, d))
        except Exception as e:
            print("API error:", e, flush=True)
            self._reply(500, {"error": "Ошибка сервера"})


def start_http():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"API для лаунчера: порт {PORT} (проверка: /api/ping)", flush=True)
    return srv


# ───────────────────────── Telegram: команды и сообщения ─────────────────────────
def who(u):
    name = " ".join(x for x in (u.get("first_name"), u.get("last_name")) if x) or "—"
    return f"{name}" + (f" (@{u['username']})" if u.get("username") else "") + f" · id {u['id']}"


ROLE_TITLE = {"moderator": "Модератор", "smm": "Директор СММ"}

HELP = ("Команды:\n"
        "/requests — новые заявки на роль\n"
        "/approve 5 — одобрить заявку №5 (выдать роль)\n"
        "/reject 5 — отклонить заявку №5\n"
        "/t 12 текст — ответ в тикет №12\n"
        "/to 123456 текст — написать человеку по chat id\n"
        "/tickets — открытые тикеты\n"
        "/close 12 — закрыть тикет\n"
        "/users — аккаунты с ролями и правами\n"
        "/role имя base|zero|moderator|smm|admin — выдать роль (сбрасывает права на роль)\n"
        "/perm имя +server — добавить право (или -server — убрать)\n"
        "   права: vg, bng, mp, server, tg, mod (модерация)\n"
        "/ban имя 10m причина — бан (m — минуты, h — часы, d — дни, perm — навсегда)\n"
        "/unban имя — снять бан\n"
        "/news текст — опубликовать новость в лаунчере (ссылка в тексте станет кнопкой)\n"
        "/newsdel 5 — удалить новость №5\n"
        "/forumdel 7 — удалить сообщение форума №7")


def parse_minutes(s):
    s = s.lower().strip()
    if s in ("perm", "навсегда", "forever"):
        return -1
    m = re.match(r"^(\d+)\s*(m|min|мин|h|ч|d|д)?$", s)
    if not m:
        return None
    mult = {"m": 1, "min": 1, "мин": 1, "h": 60, "ч": 60, "d": 1440, "д": 1440}[m.group(2) or "m"]
    return int(m.group(1)) * mult


def handle_admin(msg, chat_id, text):
    if text.strip() == "/help":
        return call("sendMessage", chat_id=ADMIN, text=HELP)
    m = re.match(r"/t\s+#?(\d+)\s+(.+)", text, re.S)
    if m:
        return call("sendMessage", chat_id=ADMIN, text=reply_ticket(int(m.group(1)), m.group(2).strip()))
    m = re.match(r"/to\s+(\d+)\s+(.+)", text, re.S)
    if m:
        r = call("sendMessage", chat_id=int(m.group(1)), text=m.group(2).strip()[:4000])
        return call("sendMessage", chat_id=ADMIN, text="✅ Отправлено" if r.get("ok") else f"❌ {r.get('description')}")
    if text.startswith("/tickets"):
        rows = rest("GET", "tickets", "status=eq.open&order=updated.desc&limit=30&select=id,subject,user_id")
        names = {}
        if rows:
            ids = ",".join(str(r["user_id"]) for r in rows)
            for u in rest("GET", "users", f"id=in.({ids})&select=id,username"):
                names[u["id"]] = u["username"]
        lines = [f"#{r['id']} · {r['subject']} · {names.get(r['user_id'], '?')}" for r in rows]
        return call("sendMessage", chat_id=ADMIN, text="Открытые тикеты:\n" + ("\n".join(lines) or "нет"))
    if text.startswith("/users"):
        rows = rest("GET", "users", "order=id.desc&limit=50&select=username,role,perms")
        return call("sendMessage", chat_id=ADMIN, text="Аккаунты:\n" + (
            "\n".join(f"{r['username']} · {r['role']} · {r['perms']}" for r in rows) or "пока нет"))
    m = re.match(r"/role\s+(\S+)\s+(base|zero|moderator|smm|admin)\b", text)
    if m:
        u = user_by_name(m.group(1))
        if not u:
            return call("sendMessage", chat_id=ADMIN, text="Пользователь не найден")
        with _db_lock:
            rest("PATCH", "users", f"id=eq.{u['id']}", body={"role": m.group(2), "perms": PRESETS[m.group(2)]},
                 prefer="return=minimal")
        return call("sendMessage", chat_id=ADMIN, text=f"✅ {m.group(1)}: роль {m.group(2)}")
    m = re.match(r"/perm\s+(\S+)\s+([+-])(vg|bng|mp|server|tg|mod)\b", text)
    if m:
        u = user_by_name(m.group(1))
        if not u:
            return call("sendMessage", chat_id=ADMIN, text="Пользователь не найден")
        perms = user_perms(u)
        if m.group(2) == "+":
            perms.add(m.group(3))
        else:
            perms.discard(m.group(3))
        new = ",".join(sorted(perms))
        with _db_lock:
            rest("PATCH", "users", f"id=eq.{u['id']}", body={"perms": new}, prefer="return=minimal")
        return call("sendMessage", chat_id=ADMIN, text=f"✅ {u['username']}: права {new or 'нет'}")
    m = re.match(r"/ban\s+(\S+)\s+(\S+)(?:\s+(.+))?", text, re.S)
    if m:
        u = user_by_name(m.group(1))
        minutes = parse_minutes(m.group(2))
        if not u:
            return call("sendMessage", chat_id=ADMIN, text="Пользователь не найден")
        if minutes is None or minutes == 0:
            return call("sendMessage", chat_id=ADMIN, text="Срок: 10m, 2h, 3d или perm")
        apply_ban(u, minutes, (m.group(3) or "").strip())
        return call("sendMessage", chat_id=ADMIN, text=f"🚫 {u['username']} забанен: {m.group(2)}")
    m = re.match(r"/unban\s+(\S+)", text)
    if m:
        u = user_by_name(m.group(1))
        if not u:
            return call("sendMessage", chat_id=ADMIN, text="Пользователь не найден")
        apply_ban(u, 0, "")
        return call("sendMessage", chat_id=ADMIN, text=f"✅ Бан снят: {u['username']}")
    if text.startswith("/close"):
        m = re.match(r"/close\s+#?(\d+)", text)
        if m:
            touch_ticket(int(m.group(1)), status="closed")
            return call("sendMessage", chat_id=ADMIN, text=f"Тикет #{m.group(1)} закрыт")
    m = re.match(r"/forumdel\s+#?(\d+)\s*$", text.strip())
    if m:
        with _db_lock:
            rest("DELETE", "forum_posts", f"id=eq.{int(m.group(1))}", prefer="return=minimal")
        return call("sendMessage", chat_id=ADMIN, text=f"Сообщение форума #{m.group(1)} удалено")
    m = re.match(r"/news\s+(.+)", text, re.S)
    if m:
        body = m.group(1).strip()[:2000]
        with _db_lock:
            rows = rest("POST", "news_posts", body={"text": body, "created": int(time.time())},
                        prefer="return=representation")
        return call("sendMessage", chat_id=ADMIN, text=f"✅ Новость #{rows[0]['id']} опубликована в лаунчере")
    m = re.match(r"/newsdel\s+#?(\d+)\s*$", text.strip())
    if m:
        with _db_lock:
            rest("DELETE", "news_posts", f"id=eq.{int(m.group(1))}", prefer="return=minimal")
        return call("sendMessage", chat_id=ADMIN, text=f"Новость #{m.group(1)} удалена")
    if text.startswith("/requests"):
        rows = rest("GET", "role_requests", "status=eq.new&order=id.asc&limit=30&select=id,username,role")
        lines = [f"#{r['id']} · {r['username']} → {ROLE_TITLE.get(r['role'], r['role'])}" for r in rows]
        return call("sendMessage", chat_id=ADMIN, text="Новые заявки:\n" + ("\n".join(lines) or "нет"))
    m = re.match(r"/(approve|reject)\s+#?(\d+)\s*$", text.strip())
    if m:
        rows = rest("GET", "role_requests", f"id=eq.{int(m.group(2))}&select=*")
        if not rows or rows[0]["status"] != "new":
            return call("sendMessage", chat_id=ADMIN, text="Заявка не найдена или уже обработана")
        req = rows[0]
        title = ROLE_TITLE.get(req["role"], req["role"])
        if m.group(1) == "approve":
            u = user_by_name(req["username"])
            if not u:
                return call("sendMessage", chat_id=ADMIN, text="Аккаунт из заявки не найден")
            with _db_lock:
                rest("PATCH", "users", f"id=eq.{int(u['id'])}",
                     body={"role": req["role"], "perms": PRESETS[req["role"]]}, prefer="return=minimal")
            status = "approved"
            admin_note = f"✅ {req['username']} получил роль «{title}»"
            player_note = f"✅ Ваша заявка на роль «{title}» одобрена. Права обновятся в лаунчере в течение 30 секунд."
        else:
            status = "rejected"
            admin_note = f"❌ Заявка #{req['id']} от {req['username']} отклонена"
            player_note = f"❌ Заявка на роль «{title}» отклонена. Вопросы — в поддержке."
        with _db_lock:
            rest("PATCH", "role_requests", f"id=eq.{int(req['id'])}", body={"status": status}, prefer="return=minimal")
        call("sendMessage", chat_id=req["tg_chat"], text=player_note)
        return call("sendMessage", chat_id=ADMIN, text=admin_note)
    rep = msg.get("reply_to_message")
    if not rep:
        return call("sendMessage", chat_id=ADMIN, text="Чтобы ответить, нажмите «Ответить» на нужное сообщение.\n"
                                                       "/help — все команды.")
    row = get_map(rep["message_id"])
    if not row:
        return call("sendMessage", chat_id=ADMIN, text="Не знаю, к какому обращению это относится (очень старое сообщение).")
    if row["kind"] == "ticket":
        return call("sendMessage", chat_id=ADMIN, text=reply_ticket(row["ref"], text),
                    reply_to_message_id=msg["message_id"])
    r = call("copyMessage", chat_id=row["ref"], from_chat_id=ADMIN, message_id=msg["message_id"])
    return call("sendMessage", chat_id=ADMIN, text="✅ Отправлено" if r.get("ok") else f"❌ {r.get('description')}",
                reply_to_message_id=msg["message_id"])


def handle(msg):
    chat_id = msg["chat"]["id"]
    text = msg.get("text", "")
    user = msg.get("from", {})

    m = re.match(r"/link\s+(\d{6})\s*$", text.strip())
    if m and chat_id != ADMIN:
        h = hashlib.sha256(m.group(1).encode()).hexdigest()
        rows = rest("GET", "account_codes", f"purpose=eq.tglink&code_hash=eq.{h}&select=*")
        if not rows or int(rows[0]["expires"]) < int(time.time()):
            return call("sendMessage", chat_id=chat_id,
                        text="Код неверный или истёк. Получите новый в лаунчере (Аккаунт → «Привязать Telegram»).")
        u = user_by_id(rows[0]["user_id"])
        with _db_lock:
            rest("PATCH", "users", f"id=eq.{int(rows[0]['user_id'])}", body={"tg_chat": chat_id},
                 prefer="return=minimal")
            rest("DELETE", "account_codes", f"user_id=eq.{int(rows[0]['user_id'])}&purpose=eq.tglink",
                 prefer="return=minimal")
        return call("sendMessage", chat_id=chat_id,
                    text=f"✅ Telegram привязан к аккаунту {u['username'] if u else ''}. "
                         "Коды подтверждения будут приходить сюда.")
    if text.strip().lower() in ("/id", "/start id"):
        return call("sendMessage", chat_id=chat_id, text=f"Ваш chat id: {chat_id}")
    if chat_id == ADMIN:
        return handle_admin(msg, chat_id, text)

    if text.startswith("/start"):
        return call("sendMessage", chat_id=chat_id,
                    text="Привет! Это поддержка BeamLDrive. Опишите проблему одним сообщением — можно со скриншотом. "
                         "Удобнее вести обращения во вкладке «Поддержка» в лаунчере.")
    if not ADMIN:
        return call("sendMessage", chat_id=chat_id, text="Поддержка пока не настроена.")
    if text.startswith("/request"):
        m = re.match(r"/request\s+(\S+)\s+(moderator|smm)\s*$", text.strip())
        if not m:
            return call("sendMessage", chat_id=chat_id,
                        text="Формат: /request логин moderator  или  /request логин smm\n"
                             "Логин — ваш логин в лаунчере.")
        if not user_by_name(m.group(1)):
            return call("sendMessage", chat_id=chat_id,
                        text="Аккаунт с таким логином не найден. Сначала зарегистрируйтесь в лаунчере.")
        if not rate_ok("req:%d" % chat_id, 3, 86400):
            return call("sendMessage", chat_id=chat_id, text="Слишком много заявок за сутки.")
        with _db_lock:
            rows = rest("POST", "role_requests", body={"username": m.group(1), "role": m.group(2),
                                                       "tg_chat": chat_id, "status": "new",
                                                       "created": int(time.time())},
                        prefer="return=representation")
        rid = rows[0]["id"]
        call("sendMessage", chat_id=ADMIN,
             text=f"📝 Заявка #{rid}: {m.group(1)} → {ROLE_TITLE[m.group(2)]}\n"
                  f"/approve {rid} — выдать  ·  /reject {rid} — отклонить")
        return call("sendMessage", chat_id=chat_id, text=f"Заявка #{rid} отправлена. Ожидайте решения.")
    if is_profane(text):
        call("sendMessage", chat_id=chat_id,
             text="Сообщение не отправлено: в нём нецензурная лексика. Опишите вопрос без мата, пожалуйста.")
        return call("sendMessage", chat_id=ADMIN, text=f"⚠️ Заблокировано сообщение с матом от {who(user)}")
    head = call("sendMessage", chat_id=ADMIN, text=f"📩 Поддержка (из Telegram)\nОт: {who(user)}")
    fwd = call("copyMessage", chat_id=ADMIN, from_chat_id=chat_id, message_id=msg["message_id"])
    if fwd.get("ok"):
        set_map(fwd["result"]["message_id"], "tguser", chat_id)
    if head.get("ok"):
        set_map(head["result"]["message_id"], "tguser", chat_id)
    call("sendMessage", chat_id=chat_id, text="Принято ✅ Мы ответим здесь.")


def main():
    if not OFFLINE:
        try:
            rest("GET", "users", "limit=1&select=id")
        except Exception as e:
            die(f"Нет связи с Supabase: {e}\nПроверьте SUPABASE_URL и SUPABASE_KEY и что таблицы созданы.")
    start_http()
    if OFFLINE:
        print("OFFLINE-режим (тест): Telegram и база отключены", flush=True)
        while True:
            time.sleep(3600)
    me = call("getMe")
    if not me.get("ok"):
        die(f"Ошибка токена или нет связи с Telegram: {me.get('description')}")
    print(f"Бот @{me['result']['username']} запущен. Админ: {ADMIN or 'не задан (напишите боту /id)'}", flush=True)
    offset = 0
    while True:
        res = call("getUpdates", offset=offset, timeout=50, allowed_updates=["message"])
        if not res.get("ok"):
            print("Ошибка:", res.get("description"), flush=True)
            time.sleep(5)
            continue
        for upd in res["result"]:
            offset = upd["update_id"] + 1
            if "message" in upd:
                try:
                    handle(upd["message"])
                except Exception as e:
                    print("Ошибка обработки:", e, flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except Exception:
        import traceback
        err = traceback.format_exc()
        try:
            (BASE / "support_bot_error.log").write_text(err, encoding="utf-8")
        except Exception:
            pass
        die("Неожиданная ошибка:\n" + err)
