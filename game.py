# -*- coding: utf-8 -*-
"""
Мини-игра "Охота за сокровищем" с намеренными уязвимостями (OWASP Top 10).
Учебный стенд для лабораторной работы. Всё приложение в одном файле.

ВНИМАНИЕ: приложение заведомо небезопасно. Запускать только локально
(127.0.0.1) или в изолированной ВМ. В интернет не выкладывать.

Уязвимости:
  1. SQL-инъекция (A03) — вход в игру, можно залогиниться Мастером без пароля.
  2. Хранимый XSS (A03) — таблица рекордов, ник выводится без экранирования.
  3. IDOR / Broken Access Control (A01) — чужой сундук по номеру в адресе.
"""
import os
import sqlite3
from flask import Flask, request, session, redirect

app = Flask(__name__)
app.secret_key = "demo-game-key"
DB = os.path.join(os.path.dirname(__file__), "game.db")

# ---------- Оформление (простая игровая обёртка) ----------
PAGE = """<!doctype html><html lang=ru><head><meta charset=utf-8>
<title>Охота за сокровищем</title><style>
body{{background:#1b1030;color:#eee;font-family:sans-serif;max-width:640px;
margin:30px auto;padding:0 16px}} a{{color:#ffd76b}}
.box{{background:#2a1a4a;padding:16px;border-radius:12px;margin:12px 0}}
input{{padding:6px;border-radius:6px;border:none}}
button{{padding:7px 14px;border:none;border-radius:6px;background:#ffd76b;cursor:pointer}}
h1{{font-size:26px}}</style></head><body>
<h1>🏴‍☠️ Охота за сокровищем</h1>{body}
<div class=box><a href="/">🏠 В таверну</a></div></body></html>"""


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


@app.route("/")
def home():
    who = session.get("nick")
    if who:
        top = ("Ты в игре как <b>{}</b> (id={}). "
               '<a href="/treasure/{}">Мой сундук</a> · '
               '<a href="/logout">выйти</a>').format(who, session["pid"], session["pid"])
    else:
        top = '<a href="/login">⚔️ Войти в игру</a>'
    body = ("<div class=box>{}</div>"
            '<div class=box>🏆 <a href="/leaderboard">Таблица рекордов</a></div>'
            ).format(top)
    return PAGE.format(body=body)


# ---------------------------------------------------------------------------
# УЯЗВИМОСТЬ 1 — SQL-инъекция. Логин собирается конкатенацией строк.
# Обход: ник = gamemaster'--  (пароль любой) -> вход Мастером без пароля.
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        nick = request.form.get("nick", "")
        pw = request.form.get("pw", "")
        # УЯЗВИМО: пользовательский ввод напрямую в SQL-запрос.
        q = ("SELECT id, nick, is_master FROM players "
             "WHERE nick='{}' AND pw='{}'").format(nick, pw)
        try:
            row = db().execute(q).fetchone()
        except sqlite3.Error as e:
            row = None
            msg = "<p>Ошибка SQL: {}</p>".format(e)
        if row:
            session["pid"] = row["id"]
            session["nick"] = row["nick"]
            if row["is_master"]:
                msg = "<p>👑 Ты вошёл как МАСТЕР! Секретный флаг: MASTER_FLAG_777</p>"
            else:
                return redirect("/")
        elif not msg:
            msg = "<p>Неверный ник или пароль.</p>"
    body = ("<div class=box><form method=post>"
            "<p>Ник: <input name=nick></p>"
            "<p>Пароль: <input name=pw type=password></p>"
            "<button>Войти</button></form>{}</div>").format(msg)
    return PAGE.format(body=body)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------------------------------------------------------------------------
# УЯЗВИМОСТЬ 2 — Хранимый XSS. Ник в таблице рекордов выводится как есть.
# Нагрузка: <script>alert('XSS')</script> исполнится у всех, кто откроет страницу.
# ---------------------------------------------------------------------------
@app.route("/leaderboard", methods=["GET", "POST"])
def leaderboard():
    c = db()
    if request.method == "POST":
        nick = request.form.get("nick", "герой")
        score = request.form.get("score", "0")
        c.execute("INSERT INTO scores (nick, score) VALUES (?,?)", (nick, score))
        c.commit()
        return redirect("/leaderboard")
    rows = c.execute("SELECT nick, score FROM scores ORDER BY id DESC").fetchall()
    items = ""
    for r in rows:
        # УЯЗВИМО: ник вставляется в HTML без экранирования.
        items += "<li>" + r["nick"] + " — " + str(r["score"]) + " 💰</li>"
    body = ("<div class=box><form method=post>"
            "<p>Ник: <input name=nick></p>"
            "<p>Очки: <input name=score></p>"
            "<button>Записать результат</button></form></div>"
            "<div class=box><h3>🏆 Рекорды</h3><ul>{}</ul></div>").format(items)
    return PAGE.format(body=body)


# ---------------------------------------------------------------------------
# УЯЗВИМОСТЬ 3 — IDOR. Сундук отдаётся по номеру без проверки владельца.
# Пример: /treasure/1 покажет сундук Мастера, хотя ты обычный игрок.
# ---------------------------------------------------------------------------
@app.route("/treasure/<int:pid>")
def treasure(pid):
    if "pid" not in session:
        return redirect("/login")
    # УЯЗВИМО: нет проверки pid == session["pid"].
    row = db().execute(
        "SELECT nick, treasure FROM players WHERE id=?", (pid,)
    ).fetchone()
    if not row:
        return PAGE.format(body="<div class=box>Сундук не найден.</div>")
    body = ("<div class=box>🧰 Сундук игрока <b>{}</b> (id={}):<br><br>"
            "💎 {}</div>").format(row["nick"], pid, row["treasure"])
    return PAGE.format(body=body)


def init_db():
    if os.path.exists(DB):
        os.remove(DB)
    c = db()
    c.executescript("""
        CREATE TABLE players(id INTEGER PRIMARY KEY AUTOINCREMENT,
            nick TEXT, pw TEXT, is_master INTEGER, treasure TEXT);
        CREATE TABLE scores(id INTEGER PRIMARY KEY AUTOINCREMENT,
            nick TEXT, score TEXT);
    """)
    c.executemany(
        "INSERT INTO players(nick,pw,is_master,treasure) VALUES (?,?,?,?)",
        [("gamemaster", "Sup3rMaster", 1, "Золотой ключ от финала: MASTER_FLAG_777"),
         ("warrior", "swordpw", 0, "Железный меч +1"),
         ("mage", "magicpw", 0, "Свиток молнии")],
    )
    c.execute("INSERT INTO scores(nick,score) VALUES ('warrior','120')")
    c.commit()
    c.close()
    print("База игры создана:", DB)


if __name__ == "__main__":
    if not os.path.exists(DB):
        init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
