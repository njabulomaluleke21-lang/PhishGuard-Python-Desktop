"""PhishGuard Desktop - Tkinter interface for the local SQLite phishing checker."""

import sqlite3
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import core


BASE_DIR = Path(__file__).resolve().parent
DATABASE_FILE = BASE_DIR / "data" / "phishing_desktop.sqlite3"


class PhishGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishGuard Desktop | Email Security")
        self.root.geometry("1030x730")
        self.root.minsize(790, 570)
        self.root.configure(bg="#09182b")

        self.connection = core.connect(DATABASE_FILE)
        self.current_user = None

        self.configure_styles()
        self.root.protocol("WM_DELETE_WINDOW", self.close_application)
        self.show_login()

    def configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background="#10243b")
        style.configure(
            "TLabel",
            background="#10243b",
            foreground="#e9f4fe",
            font=("Segoe UI", 10),
        )
        style.configure(
            "TButton",
            font=("Segoe UI", 10, "bold"),
            padding=8,
        )
        style.configure(
            "Treeview",
            background="#132943",
            foreground="white",
            fieldbackground="#132943",
            rowheight=28,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background="#205079",
            foreground="white",
            font=("Segoe UI", 9, "bold"),
        )
        style.configure("TNotebook", background="#09182b")
        style.configure(
            "TNotebook.Tab",
            padding=(17, 9),
            font=("Segoe UI", 10, "bold"),
        )

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def make_frame(self, parent=None):
        return ttk.Frame(parent or self.root, padding=22)

    def add_label(self, parent, text, size=10):
        label = ttk.Label(
            parent,
            text=text,
            font=("Segoe UI", size, "bold" if size > 12 else "normal"),
        )
        label.pack(anchor="w", pady=(5, 8))
        return label

    def add_entry(self, parent, caption, secret=False):
        self.add_label(parent, caption)
        entry = ttk.Entry(
            parent,
            width=52,
            show="●" if secret else "",
        )
        entry.pack(anchor="w", fill="x", pady=(0, 10))
        return entry

    def show_login(self):
        self.clear_window()

        wrapper = self.make_frame()
        wrapper.pack(fill="both", expand=True)

        self.add_label(wrapper, "PhishGuard Desktop", 24)
        self.add_label(
            wrapper,
            "Local phishing detection, SQLite storage and role-based access",
            11,
        )

        panel = self.make_frame(wrapper)
        panel.pack(anchor="center", pady=45, fill="x")

        self.add_label(panel, "Sign in", 19)
        self.username_entry = self.add_entry(panel, "Username")
        self.password_entry = self.add_entry(panel, "Password", secret=True)

        ttk.Button(
            panel,
            text="Sign in",
            command=self.login,
        ).pack(anchor="w", pady=8)

        self.add_label(
            panel,
            "Demo login: admin / DemoPass!2026 (change before real use)",
        )
        self.root.bind("<Return>", self.login_on_enter)

    def login_on_enter(self, event=None):
        if self.current_user is None:
            self.login()

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()

        user = core.authenticate(self.connection, username, password)
        if user is None:
            messagebox.showerror(
                "Login denied",
                "Incorrect username or password.",
            )
            return

        self.current_user = user
        core.audit(self.connection, user["username"], "Logged in")
        self.show_main_screen()

    def show_main_screen(self):
        self.root.unbind("<Return>")
        self.clear_window()

        wrapper = self.make_frame()
        wrapper.pack(fill="both", expand=True)

        header = ttk.Frame(wrapper)
        header.pack(fill="x")

        ttk.Label(
            header,
            text="PhishGuard Desktop",
            font=("Segoe UI", 21, "bold"),
        ).pack(side="left")

        ttk.Button(
            header,
            text="Log out",
            command=self.logout,
        ).pack(side="right")

        ttk.Label(
            header,
            text=f'{self.current_user["username"]}  •  {self.current_user["role"]}',
        ).pack(side="right", padx=20)

        self.tabs = ttk.Notebook(wrapper)
        self.tabs.pack(fill="both", expand=True, pady=18)

        self.dashboard_tab = self.add_tab("Dashboard")
        self.scan_tab = self.add_tab("Scan email")
        self.history_tab = self.add_tab("History")
        self.reports_tab = self.add_tab("Reports")

        if self.current_user["role"] == "admin":
            self.admin_tab = self.add_tab("Admin / backup")

        self.build_dashboard()
        self.build_scanner()
        self.build_history()
        self.build_reports()

        if self.current_user["role"] == "admin":
            self.build_admin()

        self.tabs.bind("<<NotebookTabChanged>>", self.refresh_all)

    def add_tab(self, title):
        tab = self.make_frame(self.tabs)
        self.tabs.add(tab, text=title)
        return tab

    def build_dashboard(self):
        self.add_label(self.dashboard_tab, "Your email security overview", 18)
        self.dashboard_summary = ttk.Label(
            self.dashboard_tab,
            text="",
            font=("Segoe UI", 16, "bold"),
        )
        self.dashboard_summary.pack(anchor="w", pady=14)

        self.add_label(
            self.dashboard_tab,
            "Steps: 1) Scan an email  2) Check History  "
            "3) Generate Reports  4) Back up the database",
        )
        self.add_label(
            self.dashboard_tab,
            "Rules examine urgency, sensitive information requests, "
            "rewards and suspicious links.",
        )

        ttk.Button(
            self.dashboard_tab,
            text="Open email scanner",
            command=lambda: self.tabs.select(self.scan_tab),
        ).pack(anchor="w", pady=15)

        self.refresh_dashboard()

    def refresh_dashboard(self):
        stats = core.stats(self.connection)
        self.dashboard_summary.config(
            text=(
                f"Total: {stats['total']}     "
                f"High: {stats['counts']['High']}     "
                f"Medium: {stats['counts']['Medium']}     "
                f"Low: {stats['counts']['Low']}"
            )
        )

    def build_scanner(self):
        self.add_label(self.scan_tab, "Analyze a suspicious email", 18)

        self.sender_entry = self.add_entry(
            self.scan_tab,
            "Sender email address (required)",
        )
        self.subject_entry = self.add_entry(
            self.scan_tab,
            "Subject (3–160 characters)",
        )

        self.add_label(
            self.scan_tab,
            "Email body (15–12,000 characters)",
        )
        self.email_body = tk.Text(
            self.scan_tab,
            height=9,
            bg="#081a2d",
            fg="white",
            insertbackground="white",
            font=("Segoe UI", 11),
            wrap="word",
            relief="flat",
            padx=12,
            pady=10,
        )
        self.email_body.pack(fill="both", expand=True)

        ttk.Button(
            self.scan_tab,
            text="Analyze & save to database",
            command=self.scan_email,
        ).pack(anchor="w", pady=15)

        self.scan_result = ttk.Label(
            self.scan_tab,
            text="No scan yet.",
            wraplength=820,
            justify="left",
        )
        self.scan_result.pack(anchor="w", pady=8)

    def scan_email(self):
        try:
            scan_id, result = core.save_scan(
                self.connection,
                self.current_user["id"],
                self.sender_entry.get(),
                self.subject_entry.get(),
                self.email_body.get("1.0", "end").strip(),
            )

            core.audit(
                self.connection,
                self.current_user["username"],
                f"Scanned email #{scan_id}",
            )

            reasons = " | ".join(result["reasons"])
            self.scan_result.config(
                text=(
                    f"Saved record #{scan_id}  |  "
                    f"Risk: {result['risk']}  |  "
                    f"Score: {result['score']}/100\n"
                    f"Indicators: {reasons}"
                )
            )

            self.refresh_all()
            messagebox.showinfo(
                "Scan saved",
                f"Risk: {result['risk']} ({result['score']}/100). "
                f"Record #{scan_id} saved to SQLite.",
            )
        except ValueError as error:
            messagebox.showerror("Validation error", str(error))

    def build_history(self):
        self.add_label(
            self.history_tab,
            "Saved records (actual SQLite data)",
            18,
        )

        columns = (
            "id",
            "created_at",
            "analyst",
            "sender",
            "subject",
            "risk",
            "score",
        )
        self.history_table = ttk.Treeview(
            self.history_tab,
            columns=columns,
            show="headings",
        )

        for column in columns:
            self.history_table.heading(
                column,
                text=column.replace("_", " ").title(),
            )
            width = 175 if column in ("subject", "sender") else 95
            self.history_table.column(
                column,
                width=width,
                stretch=True,
            )

        scrollbar = ttk.Scrollbar(
            self.history_tab,
            orient="vertical",
            command=self.history_table.yview,
        )
        self.history_table.configure(
            yscrollcommand=scrollbar.set,
        )
        self.history_table.pack(
            side="left",
            fill="both",
            expand=True,
        )
        scrollbar.pack(side="right", fill="y")
        self.refresh_history()

    def refresh_history(self):
        if not hasattr(self, "history_table"):
            return

        for item in self.history_table.get_children():
            self.history_table.delete(item)

        records = core.history(self.connection)
        fields = (
            "id",
            "created_at",
            "analyst",
            "sender",
            "subject",
            "risk",
            "score",
        )

        for record in records:
            values = [record[field] for field in fields]
            self.history_table.insert("", "end", values=values)

    def build_reports(self):
        self.add_label(self.reports_tab, "Live reporting", 18)

        self.report_summary = ttk.Label(
            self.reports_tab,
            text="",
            font=("Segoe UI", 16, "bold"),
        )
        self.report_summary.pack(anchor="w", pady=15)

        self.add_label(
            self.reports_tab,
            "Reports are generated from SQLite records, not sample graphics.",
        )

        ttk.Button(
            self.reports_tab,
            text="Refresh report",
            command=self.refresh_reports,
        ).pack(anchor="w", pady=8)

        ttk.Button(
            self.reports_tab,
            text="Export CSV report",
            command=self.export_report,
        ).pack(anchor="w", pady=8)

        self.refresh_reports()

    def refresh_reports(self):
        if not hasattr(self, "report_summary"):
            return

        stats = core.stats(self.connection)
        self.report_summary.config(
            text=(
                f"Total scanned: {stats['total']}\n"
                f"High risk: {stats['counts']['High']}\n"
                f"Medium risk: {stats['counts']['Medium']}\n"
                f"Low risk: {stats['counts']['Low']}"
            )
        )

    def export_report(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV file", "*.csv")],
            initialfile="phishing_desktop_report.csv",
        )
        if not file_path:
            return

        report = "\ufeff" + core.export_csv(self.connection)
        Path(file_path).write_text(report, encoding="utf-8")
        messagebox.showinfo(
            "Export complete",
            f"CSV report saved:\n{file_path}",
        )

    def build_admin(self):
        self.add_label(self.admin_tab, "Administrator controls", 18)

        fields = ttk.Frame(self.admin_tab)
        fields.pack(fill="x")

        left = self.make_frame(fields)
        left.pack(side="left", fill="both", expand=True)

        right = self.make_frame(fields)
        right.pack(side="left", fill="both", expand=True)

        self.add_label(left, "Create a user", 15)
        self.new_username = self.add_entry(left, "New username")
        self.new_password = self.add_entry(
            left,
            "New password (10+ characters)",
            secret=True,
        )

        self.add_label(left, "Role")
        self.new_role = ttk.Combobox(
            left,
            values=["analyst", "admin"],
            state="readonly",
        )
        self.new_role.set("analyst")
        self.new_role.pack(anchor="w", fill="x")

        ttk.Button(
            left,
            text="Create user",
            command=self.create_user,
        ).pack(anchor="w", pady=12)

        self.add_label(left, "Change your password", 15)
        self.old_password = self.add_entry(
            left,
            "Current password",
            secret=True,
        )
        self.updated_password = self.add_entry(
            left,
            "New password",
            secret=True,
        )

        ttk.Button(
            left,
            text="Update password",
            command=self.change_password,
        ).pack(anchor="w", pady=8)

        self.add_label(right, "Database protection", 15)
        self.add_label(
            right,
            "Back up your live database. Restore replaces all current "
            "records and accounts.",
        )

        ttk.Button(
            right,
            text="Save database backup",
            command=self.backup_database,
        ).pack(anchor="w", pady=8)

        ttk.Button(
            right,
            text="Restore database backup",
            command=self.restore_database,
        ).pack(anchor="w", pady=8)

        self.add_label(
            right,
            "Wrong credentials are rejected. Analysts cannot access this tab.",
        )

    def create_user(self):
        try:
            core.create_user(
                self.connection,
                self.new_username.get(),
                self.new_password.get(),
                self.new_role.get(),
            )
            core.audit(
                self.connection,
                self.current_user["username"],
                "Created user " + self.new_username.get(),
            )
            messagebox.showinfo("Success", "New user created.")
            self.new_username.delete(0, "end")
            self.new_password.delete(0, "end")
        except (ValueError, sqlite3.IntegrityError) as error:
            messagebox.showerror("Could not create user", str(error))

    def change_password(self):
        try:
            core.change_password(
                self.connection,
                self.current_user["id"],
                self.old_password.get(),
                self.updated_password.get(),
            )
            core.audit(
                self.connection,
                self.current_user["username"],
                "Changed own password",
            )
            messagebox.showinfo("Success", "Password changed.")
            self.old_password.delete(0, "end")
            self.updated_password.delete(0, "end")
        except ValueError as error:
            messagebox.showerror("Password error", str(error))

    def backup_database(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".sqlite3",
            initialfile="phishing_desktop_backup.sqlite3",
            filetypes=[
                ("SQLite database", "*.sqlite3"),
                ("DB file", "*.db"),
            ],
        )
        if not file_path:
            return

        try:
            core.backup(self.connection, file_path)
            core.audit(
                self.connection,
                self.current_user["username"],
                "Downloaded backup",
            )
            messagebox.showinfo(
                "Backup saved",
                f"Backup saved to:\n{file_path}",
            )
        except Exception as error:
            messagebox.showerror("Backup error", str(error))

    def restore_database(self):
        file_path = filedialog.askopenfilename(
            filetypes=[
                ("SQLite databases", "*.sqlite3 *.db"),
            ],
        )
        if not file_path:
            return

        confirmed = messagebox.askyesno(
            "Confirm restore",
            "This replaces the current desktop data and users. Continue?",
        )
        if not confirmed:
            return

        try:
            core.restore(self.connection, file_path)
            core.audit(
                self.connection,
                self.current_user["username"],
                "Restored backup",
            )
            messagebox.showinfo(
                "Restored",
                "Backup restored. Sign in again with the restored credentials.",
            )
            self.current_user = None
            self.show_login()
        except (ValueError, sqlite3.DatabaseError) as error:
            messagebox.showerror("Restore failed", str(error))

    def refresh_all(self, event=None):
        if hasattr(self, "tabs"):
            self.refresh_dashboard()
            self.refresh_history()
            self.refresh_reports()

    def logout(self):
        core.audit(
            self.connection,
            self.current_user["username"],
            "Logged out",
        )
        self.current_user = None
        self.show_login()

    def close_application(self):
        self.connection.close()
        self.root.destroy()


if __name__ == "__main__":
    main_window = tk.Tk()
    app = PhishGuardApp(main_window)
    main_window.mainloop()
