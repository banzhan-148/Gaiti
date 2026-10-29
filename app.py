"""
Block Blast — сервер регистрации, авторизации и общего рейтинга (Python + Flask).

Запуск:
    1. Положите app.py, requirements.txt и block-blast.html в одну папку.
    2. pip install -r requirements.txt
    3. python app.py            (порт по умолчанию 5000, свой:  PORT=8080 python app.py)
    4. Откройте http://localhost:5000 — игра сама включит онлайн-режим.

Другие игроки заходят по адресу вашего компьютера/хостинга, например http://192.168.1.10:5000.
Данные хранятся в файле blockblast.db (SQLite) рядом с app.py, секретный ключ подписи — в secret.key.
Для постоянной работы на хостинге:  gunicorn -w 2 -b 0.0.0.0:8000 app:app
"""
import os, re, secrets, sqlite3, time
from collections import defaultdict, deque

from flask import Flask, g, jsonify, request, send_from_directory
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "blockblast.db")
KEY_PATH = os.path.join(BASE, "secret.key")
TOKEN_TTL = 30 * 24 * 3600          # токен входа живёт 30 дней
MAX_SCORE = 2_000_000               # выше — заведомо подделка
NAME_RE = re.compile(r"^[\w\- ]{3,16}$")   # буквы (в т.ч. кириллица), цифры, _, -, пробел


def load_secret():
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    if not os.path.exists(KEY_PATH):
        with open(KEY_PATH, "w") as f:
            f.write(secrets.token_hex(32))
    with open(KEY_PATH) as f:
        return f.read().strip()


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 4096
signer = URLSafeTimedSerializer(load_secret(), salt="bb-auth")


# ---------- база данных ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    with sqlite3.connect(DB_PATH) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.execute(
            """CREATE TABLE IF NOT EXISTS users(
                   k TEXT PRIMARY KEY,           -- никнейм в нижнем регистре (уникальность)
                   name TEXT NOT NULL,
                   pw TEXT NOT NULL,             -- хэш пароля (werkzeug / scrypt)
                   best INTEGER NOT NULL DEFAULT 0,
                   games INTEGER NOT NULL DEFAULT 0,
                   created REAL NOT NULL)"""
        )
        c.execute("CREATE INDEX IF NOT EXISTS idx_best ON users(best DESC, created)")


# ---------- помощники ----------
def err(msg, code=400):
    return jsonify(error=msg), code


def rank_of(row):
    if row["best"] <= 0:
        return 0
    r = db().execute(
        "SELECT COUNT(*) FROM users WHERE best > ? OR (best = ? AND created < ?)",
        (row["best"], row["best"], row["created"]),
    ).fetchone()[0]
    return r + 1


def mine(row):
    return {"name": row["name"], "best": row["best"], "games": row["games"], "rank": rank_of(row)}


def current_user():
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        return None
    try:
        k = signer.loads(token, max_age=TOKEN_TTL)
    except (BadSignature, SignatureExpired):
        return None
    return db().execute("SELECT * FROM users WHERE k=?", (k,)).fetchone()


_attempts = defaultdict(deque)


def too_many_attempts():
    """не больше 20 попыток входа/регистрации за 10 минут с одного адреса"""
    now, q = time.time(), _attempts[request.remote_addr]
    while q and now - q[0] > 600:
        q.popleft()
    q.append(now)
    return len(q) > 20


# ---------- страницы ----------
@app.get("/")
@app.get("/block-blast.html")
def index():
    return send_from_directory(BASE, "block-blast.html")


# ---------- API ----------
@app.get("/api/ping")
def ping():
    return jsonify(ok=True)


@app.post("/api/register")
def register():
    if too_many_attempts():
        return err("Слишком много попыток, подождите несколько минут", 429)
    data = request.get_json(silent=True) or {}
    name, pw = str(data.get("name", "")).strip(), str(data.get("password", ""))
    if not NAME_RE.match(name):
        return err("Никнейм: 3–16 символов — буквы, цифры, пробел, _ и -")
    if not 6 <= len(pw) <= 100:
        return err("Пароль — минимум 6 символов")
    k = name.lower()
    try:
        db().execute(
            "INSERT INTO users(k,name,pw,created) VALUES(?,?,?,?)",
            (k, name, generate_password_hash(pw), time.time()),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return err("Этот никнейм уже занят", 409)
    row = db().execute("SELECT * FROM users WHERE k=?", (k,)).fetchone()
    return jsonify(token=signer.dumps(k), **mine(row))


@app.post("/api/login")
def login():
    if too_many_attempts():
        return err("Слишком много попыток, подождите несколько минут", 429)
    data = request.get_json(silent=True) or {}
    name, pw = str(data.get("name", "")).strip(), str(data.get("password", ""))
    row = db().execute("SELECT * FROM users WHERE k=?", (name.lower(),)).fetchone()
    if not row or not check_password_hash(row["pw"], pw):
        return err("Неверный никнейм или пароль", 401)
    return jsonify(token=signer.dumps(row["k"]), **mine(row))


@app.get("/api/me")
def me():
    u = current_user()
    return jsonify(mine(u)) if u else err("Нужно войти заново", 401)


@app.post("/api/score")
def score():
    u = current_user()
    if not u:
        return err("Нужно войти заново", 401)
    s = (request.get_json(silent=True) or {}).get("score")
    if isinstance(s, bool) or not isinstance(s, int) or not 0 < s <= MAX_SCORE:
        return err("Некорректный счёт")
    db().execute("UPDATE users SET games=games+1, best=MAX(best,?) WHERE k=?", (s, u["k"]))
    db().commit()
    return jsonify(mine(db().execute("SELECT * FROM users WHERE k=?", (u["k"],)).fetchone()))


@app.get("/api/top")
def top():
    lim = max(1, min(100, request.args.get("limit", 50, type=int)))
    rows = db().execute(
        "SELECT name,best,games FROM users WHERE best>0 ORDER BY best DESC, created LIMIT ?", (lim,)
    ).fetchall()
    u = current_user()
    return jsonify(
        top=[{"rank": i + 1, "name": r["name"], "best": r["best"], "games": r["games"]} for i, r in enumerate(rows)],
        me=mine(u) if u else None,
    )


@app.errorhandler(404)
def not_found(_):
    return err("Не найдено", 404)


@app.errorhandler(413)
def too_big(_):
    return err("Слишком большой запрос", 413)


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Block Blast: http://localhost:{port}")
    app.run(host="0.0.0.0", port=port)
