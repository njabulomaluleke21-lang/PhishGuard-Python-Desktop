# Phishing Detection System — Python desktop

A beginner-friendly student project using Python Tkinter and SQLite. It checks emails for rule-based warning signs. It does not use machine learning.

## Run in Thonny
1. Open `desktop.py` in Thonny. Keep `core.py` in the same folder.
2. Select Run > Run current script (F5).
3. Demo login: `admin` / `DemoPass!2026`. Change the password in Admin after demonstrating.

## Functions
- Login and analyst/admin roles; passwords hashed using PBKDF2.
- Email validation and rule-based risk scoring.
- Saved scan history in SQLite (`data/phishing_desktop.sqlite3` is created automatically).
- CSV reports from saved records.
- Admin creates users and backs up/restores the database.

## GitHub
Upload `desktop.py`, `core.py`, `START_DESKTOP.bat`, `.gitignore`, and this README to a new public GitHub repository. Do not upload the `data/` folder or private sample emails. GitHub hosts the code; the desktop system runs locally on your computer.

## Limits
Rule-based warnings cannot guarantee that a message is safe or malicious. For demonstration and learning, not production email security.
