# PhishGuard — Python Desktop Application

A beginner-friendly phishing email checker built with Python, Tkinter and SQLite. The detector uses a set of readable rules and warning indicators; it does not use machine learning.

## Run the application

1. Download this repository using **Code → Download ZIP**, then extract it.
2. Keep `desktop.py` and `core.py` together in the same folder.
3. Open `desktop.py` in Thonny and press **F5**, or double-click `START_DESKTOP.bat` on Windows.
4. On first run, the application creates the `data/` folder and its SQLite database automatically.

Demo login for a fresh database: **admin** / **DemoPass!2026**. Change the demo password from the Admin / backup tab before using the application with any real information.

## Main features

- Admin and analyst login roles.
- Password hashing with PBKDF2-HMAC-SHA256.
- Email address and input validation.
- Rule-based phishing warning indicators and risk scoring.
- Scan history stored in SQLite.
- Dashboard statistics and CSV report export.
- Administrator tools to create users, change passwords, and back up or restore the SQLite database.

## Database and privacy

The database is created locally at `data/phishing_desktop.sqlite3`. It stays on the computer where the application is run; it is not included in this GitHub repository. The `.gitignore` file excludes the database folder, SQLite files, CSV exports and Python cache files.

Do not commit real email contents, personal information, passwords or database backups to a public repository.

## GitHub repository

This repository contains the Python source code and run instructions. GitHub stores the project files; the desktop application runs locally on Windows with Python and Tkinter.

## Limitations

The detector is rule-based. A low score does not prove that an email is safe, and a high score is a warning for further review rather than a definitive verdict. This project is intended for learning and demonstration, not production email security.
