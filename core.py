"""Local-only phishing triage demonstration. Rule-based indicators; not a guarantee."""
import csv
import hashlib
import hmac
import io
import json
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = '''
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
 salt TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst')));
CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),
 sender TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL, risk TEXT NOT NULL,
 score INTEGER NOT NULL, reasons TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, username TEXT NOT NULL, action TEXT NOT NULL, created_at TEXT NOT NULL);
'''
DEFAULT_USER = 'admin'
DEFAULT_PASSWORD = 'DemoPass!2026'

def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

def connect(db_path):
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript(SCHEMA)
    if not db.execute('SELECT 1 FROM users LIMIT 1').fetchone():
        create_user(db, DEFAULT_USER, DEFAULT_PASSWORD, 'admin')
    return db

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 260000).hex()
    return salt, hashed

def create_user(db, username, password, role):
    if not re.fullmatch(r'[A-Za-z0-9_]{3,24}', username):
        raise ValueError('Username must be 3-24 letters, numbers or underscores.')
    if len(password) < 10:
        raise ValueError('Password must be at least 10 characters.')
    if role not in ('admin', 'analyst'):
        raise ValueError('Invalid role.')
    salt, digest = hash_password(password)
    with db:
        db.execute('INSERT INTO users(username,salt,password_hash,role) VALUES(?,?,?,?)', (username,salt,digest,role))

def authenticate(db, username, password):
    row = db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if not row:
        return None
    _, digest = hash_password(password, row['salt'])
    return dict(row) if hmac.compare_digest(digest, row['password_hash']) else None

def change_password(db, uid, old, new):
    user = db.execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()
    if not user or not authenticate(db, user['username'], old):
        raise ValueError('Current password is incorrect.')
    if len(new) < 10:
        raise ValueError('New password must have at least 10 characters.')
    salt, digest = hash_password(new)
    with db:
        db.execute('UPDATE users SET salt=?, password_hash=? WHERE id=?', (salt,digest,uid))

def validate(sender, subject, body):
    sender, subject, body = sender.strip(), subject.strip(), body.strip()
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', sender) or len(sender)>254:
        raise ValueError('Enter a valid sender email address.')
    if not (3 <= len(subject) <= 160):
        raise ValueError('Subject must be 3-160 characters.')
    if not (15 <= len(body) <= 12000):
        raise ValueError('Email body must be 15-12,000 characters.')
    return sender, subject, body

def analyze(sender, subject, body):
    sender, subject, body = validate(sender, subject, body)
    content = (subject+' '+body).lower()
    score=0; reasons=[]
    def hit(points, reason):
        nonlocal score
        score += points; reasons.append(reason)
    if re.search(r'\b(urgent|immediately|final warning|act now|account suspended|within 24 hours)\b', content):
        hit(20, 'Urgent or threatening language')
    if re.search(r'\b(password|verify your account|confirm your identity|login details|one.time password|otp)\b', content):
        hit(25, 'Requests for sensitive information or account verification')
    if re.search(r'\b(won|prize|lottery|free gift|claim your reward|inheritance)\b', content):
        hit(25, 'Unexpected reward or prize claim')
    if re.search(r'\b(bank transfer|wire transfer|gift cards?|pay a fee|payment overdue)\b', content):
        hit(20, 'Suspicious payment-related request')
    urls = re.findall(r'https?://[^\s<>"\']+', body, re.I)
    for url in urls[:20]:
        try:
            parsed = urlsplit(url.rstrip('.,);'))
            host=(parsed.hostname or '').lower()
            if parsed.scheme == 'http':
                hit(15, 'Unencrypted HTTP link')
            if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host):
                hit(25, 'Link uses a numerical IP address')
            if host.startswith('xn--') or '.xn--' in host:
                hit(20, 'Internationalized/punycode link needs verification')
            if '@' in parsed.netloc:
                hit(25, 'Link contains deceptive @ character')
            if any(x in host for x in ('secure-login-', 'account-verify', 'password-reset-')):
                hit(20, 'Link hostname imitates an account/security portal')
        except ValueError:
            hit(10,'Malformed URL')
    if len(urls)>3:
        hit(10, 'Several external links in the email')
    score=min(score,100)
    risk='High' if score>=60 else ('Medium' if score>=25 else 'Low')
    if not reasons:
        reasons=['No listed phishing indicators detected; manual verification is still necessary']
    return {'risk':risk,'score':score,'reasons':reasons}

def audit(db, username, action):
    with db:
        db.execute('INSERT INTO audit(username,action,created_at) VALUES(?,?,?)',(username,action,now()))

def save_scan(db, uid, sender, subject, body):
    sender,subject,body=validate(sender,subject,body)
    result=analyze(sender,subject,body)
    with db:
        cur=db.execute('INSERT INTO scans(user_id,sender,subject,body,risk,score,reasons,created_at) VALUES(?,?,?,?,?,?,?,?)',
            (uid,sender,subject,body,result['risk'],result['score'],json.dumps(result['reasons']),now()))
    return cur.lastrowid,result

def history(db, limit=100):
    return [dict(r) for r in db.execute('''SELECT scans.id,scans.sender,scans.subject,scans.risk,
      scans.score,scans.created_at,users.username AS analyst,scans.reasons FROM scans
      JOIN users ON scans.user_id=users.id ORDER BY scans.id DESC LIMIT ?''',(limit,))]

def stats(db):
    counts={x:0 for x in ('High','Medium','Low')}
    for row in db.execute('SELECT risk,COUNT(*) n FROM scans GROUP BY risk'):
        counts[row['risk']]=row['n']
    return {'total':sum(counts.values()),'counts':counts, 'recent':history(db,5)}

def export_csv(db):
    buf=io.StringIO(); writer=csv.writer(buf)
    writer.writerow(['ID','Date (UTC)','Analyst','Sender','Subject','Risk','Score','Indicators'])
    for r in history(db,100000):
        writer.writerow([r['id'],r['created_at'],r['analyst'],r['sender'],r['subject'],r['risk'],r['score'],'; '.join(json.loads(r['reasons']))])
    return buf.getvalue()

def backup(db, destination):
    dest=sqlite3.connect(str(destination))
    try:
        db.backup(dest)
    finally:
        dest.close()

def restore(db, source):
    source=Path(source)
    if not source.is_file() or source.stat().st_size > 50_000_000:
        raise ValueError('Please choose a valid backup under 50 MB.')
    original=sqlite3.connect(f'file:{source.as_posix()}?mode=ro',uri=True)
    try:
        check=original.execute('PRAGMA integrity_check').fetchone()
        if check is None or check[0]!='ok':
            raise ValueError('Backup database failed integrity check.')
        required={'users','scans','audit'}
        tables={x[0] for x in original.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not required.issubset(tables):
            raise ValueError('Not a backup of this system.')
        if not original.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
            raise ValueError('Backup contains no administrator.')
        db.rollback()
        db.execute('PRAGMA foreign_keys=OFF')
        original.backup(db)
        db.execute('PRAGMA foreign_keys=ON')
    finally:
        original.close()
