#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import json
import os
import secrets
import sqlite3
import string
import time
import hmac
import hashlib
from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple, List

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from PySide6.QtCore import Qt, QTimer, QEvent, QSize
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QLineEdit, QPushButton, QLabel, QMessageBox, QTableWidget, QTableWidgetItem,
    QAbstractItemView, QFormLayout, QDialog, QDialogButtonBox, QTextEdit,
    QFileDialog, QSpinBox, QCheckBox, QToolButton, QGroupBox
)

APP_TITLE = "BroPass Vault PRO 🔐"
DB_DEFAULT = "bropass_vault.db"
KDF_ITERATIONS_DEFAULT = 310_000
NONCE_LEN = 12

# ------------------ Base64 helpers ------------------

def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))

# ------------------ Crypto ------------------

def derive_key(master_password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(master_password.encode("utf-8"))

def encrypt_json(aes_key: bytes, payload: Dict[str, Any]) -> Tuple[bytes, bytes]:
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(NONCE_LEN)
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    ct = aesgcm.encrypt(nonce, data, None)
    return nonce, ct

def decrypt_json(aes_key: bytes, nonce: bytes, ciphertext: bytes) -> Dict[str, Any]:
    aesgcm = AESGCM(aes_key)
    data = aesgcm.decrypt(nonce, ciphertext, None)
    return json.loads(data.decode("utf-8"))

def now_ts() -> int:
    return int(time.time())

def human_time(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

# ------------------ TOTP (RFC 6238) ------------------
# Implementazione senza librerie esterne.
# Secret base32 (come Google Authenticator). Digits default 6, timestep 30s.

def base32_normalize(s: str) -> str:
    return "".join([c for c in (s or "").strip().replace(" ", "").upper() if c.isalnum()])

def totp_now(secret_b32: str, digits: int = 6, step: int = 30, t: Optional[int] = None) -> Tuple[str, int]:
    """
    Returns (code, remaining_seconds)
    """
    secret_b32 = base32_normalize(secret_b32)
    if not secret_b32:
        return ("", 0)

    # add padding if missing
    pad = "=" * ((8 - (len(secret_b32) % 8)) % 8)
    secret_b32_padded = secret_b32 + pad

    try:
        key = base64.b32decode(secret_b32_padded, casefold=True)
    except Exception:
        return ("", 0)

    if t is None:
        t = int(time.time())
    counter = t // step
    remaining = step - (t % step)

    msg = counter.to_bytes(8, "big")
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    dbc = int.from_bytes(h[offset:offset+4], "big") & 0x7fffffff
    code = dbc % (10 ** digits)
    return (str(code).zfill(digits), remaining)

# ------------------ Utils ------------------

def normalize_tags(tags: str) -> str:
    tags = tags or ""
    parts = []
    for t in tags.replace(";", ",").split(","):
        t = t.strip()
        if t:
            parts.append(t.lower())
    seen = set()
    out = []
    for t in parts:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return ",".join(out)

def generate_password(length: int = 20, no_symbols: bool = False, no_ambiguous: bool = True) -> str:
    letters = string.ascii_letters
    digits = string.digits
    symbols = "!@#$%^&*()-_=+[]{};:,.?/"

    ambiguous = set("O0Il1|`'\"")
    pool = letters + digits + ("" if no_symbols else symbols)
    if no_ambiguous:
        pool = "".join([c for c in pool if c not in ambiguous])

    length = max(8, min(128, int(length)))

    chosen = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(digits),
    ]
    if not no_symbols:
        chosen.append(secrets.choice(symbols))

    while len(chosen) < length:
        chosen.append(secrets.choice(pool))

    secrets.SystemRandom().shuffle(chosen)
    return "".join(chosen)

# ------------------ DB ------------------

def connect_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db(conn: sqlite3.Connection, iterations: int) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            salt_b64 TEXT NOT NULL,
            kdf_iterations INTEGER NOT NULL
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            username TEXT,
            url TEXT,
            tags TEXT,
            notes TEXT,
            nonce_b64 TEXT NOT NULL,
            ciphertext_b64 TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
    """)
    cur = conn.execute("SELECT salt_b64, kdf_iterations FROM meta WHERE id=1;")
    row = cur.fetchone()
    if row is None:
        salt = secrets.token_bytes(16)
        conn.execute(
            "INSERT INTO meta (id, salt_b64, kdf_iterations) VALUES (1, ?, ?);",
            (b64e(salt), iterations)
        )
        conn.commit()

def load_meta(conn: sqlite3.Connection) -> Tuple[bytes, int]:
    cur = conn.execute("SELECT salt_b64, kdf_iterations FROM meta WHERE id=1;")
    row = cur.fetchone()
    if not row:
        raise RuntimeError("Meta non presente. Inizializza il vault.")
    return b64d(row[0]), int(row[1])

@dataclass
class VaultSession:
    conn: sqlite3.Connection
    key: bytes
    db_path: str

def open_vault(db_path: str, master_password: str, create_if_missing: bool = False) -> VaultSession:
    if create_if_missing and not os.path.exists(db_path):
        conn = connect_db(db_path)
        init_db(conn, KDF_ITERATIONS_DEFAULT)
        conn.close()

    conn = connect_db(db_path)
    init_db(conn, KDF_ITERATIONS_DEFAULT)
    salt, iters = load_meta(conn)
    key = derive_key(master_password, salt, iters)

    # validate password by trying decrypt on first entry if exists
    cur = conn.execute("SELECT nonce_b64, ciphertext_b64 FROM entries LIMIT 1;")
    row = cur.fetchone()
    if row:
        try:
            _ = decrypt_json(key, b64d(row[0]), b64d(row[1]))
        except Exception:
            conn.close()
            raise ValueError("Master password errata.")
    return VaultSession(conn=conn, key=key, db_path=db_path)

def db_list(sess: VaultSession, query: str = "") -> List[Tuple]:
    q = (query or "").strip()
    if q:
        like = f"%{q}%"
        cur = sess.conn.execute("""
            SELECT id, title, username, url, tags, updated_at
            FROM entries
            WHERE title LIKE ? OR username LIKE ? OR url LIKE ? OR tags LIKE ?
            ORDER BY updated_at DESC;
        """, (like, like, like, like))
    else:
        cur = sess.conn.execute("""
            SELECT id, title, username, url, tags, updated_at
            FROM entries
            ORDER BY updated_at DESC;
        """)
    return cur.fetchall()

def db_get(sess: VaultSession, entry_id: int) -> Dict[str, Any]:
    cur = sess.conn.execute("""
        SELECT id, title, username, url, tags, notes, nonce_b64, ciphertext_b64, created_at, updated_at
        FROM entries WHERE id=?;
    """, (entry_id,))
    row = cur.fetchone()
    if not row:
        raise KeyError("ID non trovato.")
    payload = decrypt_json(sess.key, b64d(row[6]), b64d(row[7]))
    return {
        "id": row[0],
        "title": row[1],
        "username": row[2] or "",
        "url": row[3] or "",
        "tags": row[4] or "",
        "notes": row[5] or "",
        "password": payload.get("password", ""),
        "totp_secret": payload.get("totp_secret", ""),  # NEW
        "created_at": row[8],
        "updated_at": row[9],
    }

def db_add(sess: VaultSession, title: str, username: str, password: str, url: str, tags: str, notes: str, totp_secret: str) -> int:
    payload = {
        "password": password,
        "username": username or "",
        "url": url or "",
        "notes": notes or "",
        "totp_secret": base32_normalize(totp_secret or ""),
    }
    nonce, ct = encrypt_json(sess.key, payload)
    ts = now_ts()
    cur = sess.conn.execute("""
        INSERT INTO entries (title, username, url, tags, notes, nonce_b64, ciphertext_b64, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
    """, (
        title, username or "", url or "", normalize_tags(tags), notes or "",
        b64e(nonce), b64e(ct), ts, ts
    ))
    sess.conn.commit()
    return int(cur.lastrowid)

def db_update(sess: VaultSession, entry_id: int, title: str, username: str, password: str, url: str, tags: str, notes: str, totp_secret: str) -> None:
    payload = {
        "password": password,
        "username": username or "",
        "url": url or "",
        "notes": notes or "",
        "totp_secret": base32_normalize(totp_secret or ""),
    }
    nonce, ct = encrypt_json(sess.key, payload)
    ts = now_ts()
    sess.conn.execute("""
        UPDATE entries
        SET title=?, username=?, url=?, tags=?, notes=?, nonce_b64=?, ciphertext_b64=?, updated_at=?
        WHERE id=?;
    """, (
        title, username or "", url or "", normalize_tags(tags), notes or "",
        b64e(nonce), b64e(ct), ts, entry_id
    ))
    sess.conn.commit()

def db_delete(sess: VaultSession, entry_id: int) -> None:
    sess.conn.execute("DELETE FROM entries WHERE id=?;", (entry_id,))
    sess.conn.commit()

# Export/import cifrato (backup)
def export_encrypted(sess: VaultSession, out_file: str) -> None:
    cur = sess.conn.execute("""
        SELECT id, title, username, url, tags, notes, nonce_b64, ciphertext_b64, created_at, updated_at
        FROM entries ORDER BY id ASC;
    """)
    entries = []
    for r in cur.fetchall():
        entries.append({
            "id": r[0], "title": r[1], "username": r[2], "url": r[3], "tags": r[4], "notes": r[5],
            "nonce_b64": r[6], "ciphertext_b64": r[7], "created_at": r[8], "updated_at": r[9],
        })
    payload = {"format": "bropass-export-v2", "exported_at": now_ts(), "entries": entries}
    nonce, ct = encrypt_json(sess.key, payload)
    blob = {"format": "bropass-export-wrapper-v1", "nonce_b64": b64e(nonce), "ciphertext_b64": b64e(ct)}
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(blob, f, ensure_ascii=False, indent=2)

def import_encrypted(sess: VaultSession, in_file: str, merge: bool) -> None:
    with open(in_file, "r", encoding="utf-8") as f:
        blob = json.load(f)
    if blob.get("format") != "bropass-export-wrapper-v1":
        raise ValueError("Formato backup non supportato.")

    nonce = b64d(blob["nonce_b64"])
    ct = b64d(blob["ciphertext_b64"])
    payload = decrypt_json(sess.key, nonce, ct)

    entries = payload.get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("Backup corrotto (entries).")

    if not merge:
        sess.conn.execute("DELETE FROM entries;")
        sess.conn.commit()

    for e in entries:
        sess.conn.execute("""
            INSERT INTO entries (title, username, url, tags, notes, nonce_b64, ciphertext_b64, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            e.get("title", ""), e.get("username", ""), e.get("url", ""),
            e.get("tags", ""), e.get("notes", ""),
            e.get("nonce_b64", ""), e.get("ciphertext_b64", ""),
            int(e.get("created_at", now_ts())), int(e.get("updated_at", now_ts())),
        ))
    sess.conn.commit()

# ------------------ Dialogs ------------------

class LoginDialog(QDialog):
    def __init__(self, parent=None, initial_db=DB_DEFAULT):
        super().__init__(parent)
        self.setWindowTitle("Apri Vault")
        self.setMinimumWidth(520)

        self.db_edit = QLineEdit(initial_db)
        self.pw_edit = QLineEdit()
        self.pw_edit.setEchoMode(QLineEdit.Password)

        self.create_chk = QCheckBox("Crea nuovo vault (se non esiste)")
        self.create_chk.setChecked(True)

        browse_btn = QPushButton("Sfoglia…")
        browse_btn.clicked.connect(self.browse)

        form = QFormLayout()
        row = QHBoxLayout()
        row.addWidget(self.db_edit)
        row.addWidget(browse_btn)
        form.addRow("Database (vault):", row)
        form.addRow("", self.create_chk)
        form.addRow("Master password:", self.pw_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(buttons)

    def browse(self):
        path, _ = QFileDialog.getSaveFileName(self, "Seleziona o crea DB", self.db_edit.text(), "SQLite DB (*.db);;Tutti i file (*.*)")
        if path:
            self.db_edit.setText(path)

    def data(self) -> Tuple[str, str, bool]:
        return self.db_edit.text().strip(), self.pw_edit.text(), self.create_chk.isChecked()

class EntryDialog(QDialog):
    def __init__(self, parent=None, title="Entry", data: Optional[Dict[str, Any]] = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(QSize(560, 520))

        data = data or {}
        self.title_edit = QLineEdit(data.get("title", ""))
        self.user_edit = QLineEdit(data.get("username", ""))
        self.url_edit = QLineEdit(data.get("url", ""))
        self.tags_edit = QLineEdit(data.get("tags", ""))
        self.pw_edit = QLineEdit(data.get("password", ""))
        self.pw_edit.setEchoMode(QLineEdit.Password)
        self.totp_edit = QLineEdit(data.get("totp_secret", ""))  # base32
        self.notes_edit = QTextEdit(data.get("notes", ""))

        self.show_btn = QToolButton()
        self.show_btn.setText("👁")
        self.show_btn.clicked.connect(self.toggle_pw)
        self.pw_visible = False

        self.gen_btn = QToolButton()
        self.gen_btn.setText("🎲")
        self.gen_btn.clicked.connect(self.gen_pw)

        self.len_spin = QSpinBox()
        self.len_spin.setRange(8, 128)
        self.len_spin.setValue(20)
        self.no_symbols = QCheckBox("Senza simboli")
        self.no_amb = QCheckBox("Evita ambigui (O0Il)")
        self.no_amb.setChecked(True)

        gen_row = QHBoxLayout()
        gen_row.addWidget(QLabel("Lunghezza:"))
        gen_row.addWidget(self.len_spin)
        gen_row.addWidget(self.no_symbols)
        gen_row.addWidget(self.no_amb)
        gen_row.addStretch(1)

        pw_row = QHBoxLayout()
        pw_row.addWidget(self.pw_edit)
        pw_row.addWidget(self.show_btn)
        pw_row.addWidget(self.gen_btn)

        form = QFormLayout()
        form.addRow("Titolo*", self.title_edit)
        form.addRow("Username", self.user_edit)
        form.addRow("URL", self.url_edit)
        form.addRow("Tags (coma)", self.tags_edit)
        form.addRow("Password*", pw_row)

        totp_box = QGroupBox("TOTP 2FA (opzionale)")
        totp_l = QVBoxLayout(totp_box)
        totp_l.addWidget(QLabel("Inserisci il secret Base32 (come in Google Authenticator). Esempio: JBSWY3DPEHPK3PXP"))
        totp_l.addWidget(self.totp_edit)
        form.addRow(totp_box)

        form.addRow("Generatore", gen_row)
        form.addRow("Note", self.notes_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Save)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        root = QVBoxLayout(self)
        root.addLayout(form)
        root.addWidget(buttons)

    def toggle_pw(self):
        self.pw_visible = not self.pw_visible
        self.pw_edit.setEchoMode(QLineEdit.Normal if self.pw_visible else QLineEdit.Password)

    def gen_pw(self):
        pwd = generate_password(
            length=int(self.len_spin.value()),
            no_symbols=self.no_symbols.isChecked(),
            no_ambiguous=self.no_amb.isChecked()
        )
        self.pw_edit.setText(pwd)

    def value(self) -> Dict[str, Any]:
        return {
            "title": self.title_edit.text().strip(),
            "username": self.user_edit.text().strip(),
            "url": self.url_edit.text().strip(),
            "tags": self.tags_edit.text().strip(),
            "password": self.pw_edit.text(),
            "totp_secret": self.totp_edit.text().strip(),
            "notes": self.notes_edit.toPlainText().strip(),
        }

# ------------------ Main Window ------------------

class BroPassPro(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setMinimumSize(1100, 600)

        self.sess: Optional[VaultSession] = None
        self._db_path: str = DB_DEFAULT

        # Auto-lock
        self.lock_minutes = 3  # default
        self._last_activity = time.time()
        self._lock_timer = QTimer(self)
        self._lock_timer.setInterval(1000)
        self._lock_timer.timeout.connect(self._tick_lock)
        self._lock_timer.start()

        # TOTP refresh
        self._totp_timer = QTimer(self)
        self._totp_timer.setInterval(500)
        self._totp_timer.timeout.connect(self._refresh_totp_panel)
        self._totp_timer.start()

        self._build_ui()
        self._build_menu()

        # Track user activity
        QApplication.instance().installEventFilter(self)

        # Login
        QTimer.singleShot(50, self.login_flow)

    def eventFilter(self, obj, event):
        # reset activity on most user interactions
        if event.type() in (QEvent.MouseMove, QEvent.MouseButtonPress, QEvent.KeyPress, QEvent.Wheel):
            self._last_activity = time.time()
        return super().eventFilter(obj, event)

    def _build_menu(self):
        menubar = self.menuBar()

        filem = menubar.addMenu("File")
        act_open = QAction("Cambia vault…", self)
        act_open.triggered.connect(self.change_vault)
        filem.addAction(act_open)

        act_export = QAction("Export backup cifrato…", self)
        act_export.triggered.connect(self.export_backup)
        filem.addAction(act_export)

        act_import = QAction("Import backup cifrato…", self)
        act_import.triggered.connect(self.import_backup)
        filem.addAction(act_import)

        filem.addSeparator()
        act_quit = QAction("Esci", self)
        act_quit.setShortcut(QKeySequence.Quit)
        act_quit.triggered.connect(self.close)
        filem.addAction(act_quit)

        secm = menubar.addMenu("Sicurezza")
        self.act_lock = QAction("Blocca ora", self)
        self.act_lock.setShortcut(QKeySequence("Ctrl+L"))
        self.act_lock.triggered.connect(self.lock_now)
        secm.addAction(self.act_lock)

        self.act_lock_min = QAction("Auto-lock…", self)
        self.act_lock_min.triggered.connect(self.set_lock_minutes)
        secm.addAction(self.act_lock_min)

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        # Top bar
        top = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Cerca (titolo, username, url, tags)…")
        self.search.textChanged.connect(self.refresh_list)

        self.btn_add = QPushButton("➕ Aggiungi")
        self.btn_edit = QPushButton("✏️ Modifica")
        self.btn_del = QPushButton("🗑️ Elimina")
        self.btn_copy = QPushButton("📋 Copia password")
        self.btn_show = QPushButton("👁 Mostra 10s")
        self.btn_totp = QPushButton("🔐 Copia TOTP")

        self.btn_add.clicked.connect(self.add_entry)
        self.btn_edit.clicked.connect(self.edit_entry)
        self.btn_del.clicked.connect(self.delete_entry)
        self.btn_copy.clicked.connect(self.copy_password)
        self.btn_show.clicked.connect(self.show_password_temp)
        self.btn_totp.clicked.connect(self.copy_totp)

        top.addWidget(QLabel("Buscar:"))
        top.addWidget(self.search, 1)
        top.addWidget(self.btn_add)
        top.addWidget(self.btn_edit)
        top.addWidget(self.btn_del)
        top.addWidget(self.btn_copy)
        top.addWidget(self.btn_show)
        top.addWidget(self.btn_totp)

        root.addLayout(top)

        # Split
        split = QSplitter(Qt.Horizontal)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["ID", "Titolo", "Username", "URL", "Tags", "Aggiornato"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.itemSelectionChanged.connect(self.load_details)

        split.addWidget(self.table)

        # Right panel
        right = QWidget()
        rlay = QVBoxLayout(right)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)

        self.totp_label = QLabel("TOTP: —")
        self.totp_label.setStyleSheet("font-size: 20px; font-weight: 700;")

        self.totp_meta = QLabel("—")
        self.totp_meta.setStyleSheet("color: #666;")

        rlay.addWidget(QLabel("Dettagli:"))
        rlay.addWidget(self.detail, 1)
        rlay.addWidget(self.totp_label)
        rlay.addWidget(self.totp_meta)

        split.addWidget(right)
        split.setSizes([720, 380])

        root.addWidget(split, 1)

        # Status
        self.status = QLabel("Pronto.")
        self.status.setStyleSheet("color: #444; padding: 6px;")
        root.addWidget(self.status)

    # ------------------ Session / Lock ------------------

    def _tick_lock(self):
        if not self.sess:
            return
        idle = time.time() - self._last_activity
        remain = max(0, int(self.lock_minutes * 60 - idle))
        self.status.setText(
            f"Vault: {os.path.basename(self.sess.db_path)} | Auto-lock: {self.lock_minutes} min | Inattivo: {int(idle)}s | Blocco tra: {remain}s"
        )
        if idle >= self.lock_minutes * 60:
            self.lock_now()

    def lock_now(self):
        if self.sess:
            try:
                self.sess.conn.close()
            except Exception:
                pass
        self.sess = None
        self.table.setRowCount(0)
        self.detail.setPlainText("")
        self.totp_label.setText("TOTP: —")
        self.totp_meta.setText("—")
        QMessageBox.information(self, "Bloccato", "Vault bloccato. Inserisci di nuovo la master password.")
        self.login_flow()

    def set_lock_minutes(self):
        val, ok = QFileDialog.getSaveFileName  # dummy to keep lint quiet
        minutes, ok = self._ask_int("Auto-lock", "Minuti di inattività prima del blocco:", self.lock_minutes, 1, 120)
        if ok:
            self.lock_minutes = minutes
            self._last_activity = time.time()

    def _ask_int(self, title: str, label: str, current: int, mn: int, mx: int) -> Tuple[int, bool]:
        dlg = QDialog(self)
        dlg.setWindowTitle(title)
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(label))
        spin = QSpinBox()
        spin.setRange(mn, mx)
        spin.setValue(current)
        lay.addWidget(spin)
        bb = QDialogButtonBox(QDialogButtonBox.Cancel | QDialogButtonBox.Ok)
        bb.accepted.connect(dlg.accept)
        bb.rejected.connect(dlg.reject)
        lay.addWidget(bb)
        ok = dlg.exec() == QDialog.Accepted
        return spin.value(), ok

    def login_flow(self):
        dlg = LoginDialog(self, self._db_path)
        if dlg.exec() != QDialog.Accepted:
            self.close()
            return

        db_path, mp, create_if_missing = dlg.data()
        if not db_path or not mp:
            QMessageBox.warning(self, "Errore", "DB e master password sono obbligatori.")
            return

        try:
            sess = open_vault(db_path, mp, create_if_missing=create_if_missing)
        except Exception as e:
            QMessageBox.critical(self, "Login fallito", str(e))
            return self.login_flow()

        self.sess = sess
        self._db_path = db_path
        self._last_activity = time.time()
        self.refresh_list()

    def change_vault(self):
        self.lock_now()

    # ------------------ Table / selection ------------------

    def refresh_list(self):
        if not self.sess:
            return
        rows = db_list(self.sess, self.search.text())
        self.table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            _id, title, user, url, tags, upd = row
            items = [
                QTableWidgetItem(str(_id)),
                QTableWidgetItem(title or ""),
                QTableWidgetItem(user or ""),
                QTableWidgetItem(url or ""),
                QTableWidgetItem(tags or ""),
                QTableWidgetItem(human_time(int(upd))),
            ]
            for c, it in enumerate(items):
                it.setFlags(it.flags() & ~Qt.ItemIsEditable)
                self.table.setItem(r, c, it)
        self.table.resizeColumnsToContents()
        if rows:
            self.table.selectRow(0)
            self.load_details()

    def selected_id(self) -> Optional[int]:
        sel = self.table.currentRow()
        if sel < 0:
            return None
        item = self.table.item(sel, 0)
        if not item:
            return None
        return int(item.text())

    def load_details(self):
        if not self.sess:
            return
        entry_id = self.selected_id()
        if entry_id is None:
            self.detail.setPlainText("")
            return
        try:
            e = db_get(self.sess, entry_id)
        except Exception as ex:
            self.detail.setPlainText(f"Errore: {ex}")
            return

        txt = (
            f"Titolo: {e['title']}\n"
            f"Username: {e['username'] or '-'}\n"
            f"URL: {e['url'] or '-'}\n"
            f"Tags: {e['tags'] or '-'}\n"
            f"Aggiornato: {human_time(int(e['updated_at']))}\n"
            f"Creato: {human_time(int(e['created_at']))}\n"
            f"\nNote:\n{e['notes'] or '-'}\n"
            f"\nPassword: ******** (usa Copia / Mostra)\n"
            f"TOTP secret: {'(presente)' if e.get('totp_secret') else '(assente)'}"
        )
        self.detail.setPlainText(txt)
        self._refresh_totp_panel()

    # ------------------ CRUD ------------------

    def add_entry(self):
        if not self.sess:
            return
        dlg = EntryDialog(self, "Aggiungi entry")
        if dlg.exec() != QDialog.Accepted:
            return
        d = dlg.value()
        if not d["title"] or not d["password"]:
            return QMessageBox.warning(self, "Errore", "Titolo e password sono obbligatori.")
        try:
            new_id = db_add(self.sess, d["title"], d["username"], d["password"], d["url"], d["tags"], d["notes"], d["totp_secret"])
            self._last_activity = time.time()
            self.refresh_list()
            self._select_id(new_id)
        except Exception as ex:
            QMessageBox.critical(self, "Errore", str(ex))

    def edit_entry(self):
        if not self.sess:
            return
        entry_id = self.selected_id()
        if entry_id is None:
            return QMessageBox.information(self, "Info", "Seleziona una voce.")
        try:
            e = db_get(self.sess, entry_id)
        except Exception as ex:
            return QMessageBox.critical(self, "Errore", str(ex))

        dlg = EntryDialog(self, f"Modifica entry (ID {entry_id})", data=e)
        if dlg.exec() != QDialog.Accepted:
            return
        d = dlg.value()
        if not d["title"] or not d["password"]:
            return QMessageBox.warning(self, "Errore", "Titolo e password sono obbligatori.")
        try:
            db_update(self.sess, entry_id, d["title"], d["username"], d["password"], d["url"], d["tags"], d["notes"], d["totp_secret"])
            self._last_activity = time.time()
            self.refresh_list()
            self._select_id(entry_id)
        except Exception as ex:
            QMessageBox.critical(self, "Errore", str(ex))

    def delete_entry(self):
        if not self.sess:
            return
        entry_id = self.selected_id()
        if entry_id is None:
            return QMessageBox.information(self, "Info", "Seleziona una voce.")
        if QMessageBox.question(self, "Conferma", f"Eliminare ID {entry_id}?") != QMessageBox.Yes:
            return
        try:
            db_delete(self.sess, entry_id)
            self._last_activity = time.time()
            self.refresh_list()
        except Exception as ex:
            QMessageBox.critical(self, "Errore", str(ex))

    def _select_id(self, entry_id: int):
        for r in range(self.table.rowCount()):
            it = self.table.item(r, 0)
            if it and it.text() == str(entry_id):
                self.table.selectRow(r)
                return

    # ------------------ Secrets actions ------------------

    def copy_password(self):
        if not self.sess:
            return
        entry_id = self.selected_id()
        if entry_id is None:
            return
        try:
            e = db_get(self.sess, entry_id)
            QApplication.clipboard().setText(e["password"])
            self._last_activity = time.time()
            self.status.setText("Password copiata negli appunti.")
        except Exception as ex:
            QMessageBox.critical(self, "Errore", str(ex))

    def show_password_temp(self):
        if not self.sess:
            return
        entry_id = self.selected_id()
        if entry_id is None:
            return
        try:
            e = db_get(self.sess, entry_id)
        except Exception as ex:
            return QMessageBox.critical(self, "Errore", str(ex))

        dlg = QDialog(self)
        dlg.setWindowTitle("Password (temporanea 10s)")
        lay = QVBoxLayout(dlg)
        lay.addWidget(QLabel(f"{e['title']} (ID {e['id']})"))
        pw = QLineEdit(e["password"])
        pw.setReadOnly(True)
        lay.addWidget(pw)

        btn = QPushButton("Copia")
        btn.clicked.connect(lambda: QApplication.clipboard().setText(e["password"]))
        lay.addWidget(btn)

        info = QLabel("Si chiude automaticamente in 10 secondi.")
        info.setStyleSheet("color:#666;")
        lay.addWidget(info)

        timer = QTimer(dlg)
        timer.setSingleShot(True)
        timer.timeout.connect(dlg.accept)
        timer.start(10_000)

        self._last_activity = time.time()
        dlg.exec()

    # ------------------ TOTP panel ------------------

    def _refresh_totp_panel(self):
        if not self.sess:
            return
        entry_id = self.selected_id()
        if entry_id is None:
            self.totp_label.setText("TOTP: —")
            self.totp_meta.setText("—")
            return
        try:
            e = db_get(self.sess, entry_id)
        except Exception:
            return
        secret = e.get("totp_secret", "") or ""
        code, rem = totp_now(secret, digits=6, step=30)
        if not secret:
            self.totp_label.setText("TOTP: —")
            self.totp_meta.setText("Nessun secret TOTP per questa voce.")
        elif not code:
            self.totp_label.setText("TOTP: ?")
            self.totp_meta.setText("Secret TOTP non valido (controlla Base32).")
        else:
            self.totp_label.setText(f"TOTP: {code}")
            self.totp_meta.setText(f"Scade tra {rem}s")

    def copy_totp(self):
        if not self.sess:
            return
        entry_id = self.selected_id()
        if entry_id is None:
            return
        try:
            e = db_get(self.sess, entry_id)
            code, _ = totp_now(e.get("totp_secret", ""), digits=6, step=30)
            if not code:
                return QMessageBox.information(self, "TOTP", "Nessun TOTP valido per questa voce.")
            QApplication.clipboard().setText(code)
            self._last_activity = time.time()
            self.status.setText("TOTP copiato negli appunti.")
        except Exception as ex:
            QMessageBox.critical(self, "Errore", str(ex))

    # ------------------ Backup ------------------

    def export_backup(self):
        if not self.sess:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export backup cifrato", "bropass_backup.enc.json", "Backup cifrato (*.enc.json);;Tutti i file (*.*)")
        if not path:
            return
        try:
            export_encrypted(self.sess, path)
            QMessageBox.information(self, "Export", "Backup cifrato esportato.")
        except Exception as ex:
            QMessageBox.critical(self, "Errore", str(ex))

    def import_backup(self):
        if not self.sess:
            return
        path, _ = QFileDialog.getOpenFileName(self, "Import backup cifrato", "", "Backup cifrato (*.enc.json);;Tutti i file (*.*)")
        if not path:
            return

        merge = QMessageBox.question(self, "Import", "Vuoi fare MERGE (Sì) o SOVRASCRIVERE tutto (No)?") == QMessageBox.Yes
        try:
            import_encrypted(self.sess, path, merge=merge)
            QMessageBox.information(self, "Import", "Import completato.")
            self.refresh_list()
        except Exception as ex:
            QMessageBox.critical(self, "Errore", str(ex))


def main():
    app = QApplication([])
    w = BroPassPro()
    w.show()
    app.exec()

if __name__ == "__main__":
    main()



