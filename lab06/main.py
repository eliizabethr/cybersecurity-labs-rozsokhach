import os
import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox

DB_FILE = "students.db"


def open_db():
    return sqlite3.connect(DB_FILE)


def build_database():
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
        except OSError:
            pass

    con = open_db()
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name  TEXT NOT NULL,
            faculty    TEXT NOT NULL,
            avg_grade  REAL NOT NULL
        )
    """)

    rows = [
        ("Максим", "Більченко", "Інженерія програмного забезпечення", 88.0),
        ("Андрій", "Дашков", "Інженерія програмного забезпечення", 76.8),
        ("Єлизавета", "Розсохач", "Інженерія програмного забезпечення", 82.4),
        ("Владислав", "Євтушенко", "Інженерія програмного забезпечення", 84.9),
        ("Яна", "Махиня", "Інженерія програмного забезпечення", 90.5),
        ("Давід", "Пахомов", "Інженерія програмного забезпечення", 92.1),
        ("Валерій", "Швидкой", "Інженерія програмного забезпечення", 95.8),
    ]
    cur.executemany(
        "INSERT INTO students(first_name, last_name, faculty, avg_grade) VALUES (?, ?, ?, ?)",
        rows
    )

    con.commit()
    con.close()


def unsafe_search_by_name(user_text: str):
    sql = f"SELECT id, first_name, last_name, faculty, avg_grade FROM students WHERE last_name = '{user_text}'"
    con = open_db()
    try:
        rows = con.execute(sql).fetchall()
        return rows, sql, None
    except Exception as e:
        return [], sql, str(e)
    finally:
        con.close()


def safe_search_by_name(user_text: str):
    sql = "SELECT id, first_name, last_name, faculty, avg_grade FROM students WHERE last_name = ?"
    con = open_db()
    try:
        rows = con.execute(sql, (user_text,)).fetchall()
        shown_sql = f"{sql}    [params=({user_text!r},)]"
        return rows, shown_sql, None
    except Exception as e:
        return [], sql, str(e)
    finally:
        con.close()


class SQLiDemoUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("SQL Injection Demo")
        root.geometry("980x480")

        top = ttk.Frame(root, padding=12)
        top.pack(fill="x")

        ttk.Label(top, text="Пошук студента за прізвищем:", font=("Arial", 12, "bold")).pack(anchor="w")
        self.entry = ttk.Entry(top, font=("Consolas", 11))
        self.entry.pack(fill="x", pady=(6, 10))

        btns = ttk.Frame(top)
        btns.pack(fill="x")

        ttk.Button(btns, text="🔴 Пошук (вразливий)", command=self.on_unsafe).pack(
            side="left", expand=True, fill="x", padx=(0, 6)
        )
        ttk.Button(btns, text="🟢 Пошук (безпечний)", command=self.on_safe).pack(
            side="left", expand=True, fill="x", padx=(6, 0)
        )

        self.sql_view = tk.Text(root, height=3, font=("Consolas", 10))
        self.sql_view.pack(fill="x", padx=12)
        self.sql_view.insert("1.0", "Тут буде показано SQL-запит...")
        self.sql_view.configure(state="disabled")

        table_frame = ttk.Frame(root, padding=12)
        table_frame.pack(fill="both", expand=True)

        cols = ("id", "first_name", "last_name", "faculty", "avg_grade")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")
        self.tree.heading("id", text="ID")
        self.tree.heading("first_name", text="Імʼя")
        self.tree.heading("last_name", text="Прізвище")
        self.tree.heading("faculty", text="Факультет")
        self.tree.heading("avg_grade", text="Середній бал")

        self.tree.column("id", width=60, anchor="center")
        self.tree.column("first_name", width=170, anchor="e")
        self.tree.column("last_name", width=170, anchor="e")
        self.tree.column("faculty", width=280, anchor="e")
        self.tree.column("avg_grade", width=120, anchor="center")

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")

    def set_sql_text(self, text: str):
        self.sql_view.configure(state="normal")
        self.sql_view.delete("1.0", tk.END)
        self.sql_view.insert("1.0", text)
        self.sql_view.configure(state="disabled")

    def fill_table(self, rows):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for r in rows:
            self.tree.insert("", "end", values=r)

    def on_unsafe(self):
        user_text = self.entry.get()
        rows, sql, err = unsafe_search_by_name(user_text)
        self.set_sql_text("SQL-запит: " + sql)

        if err:
            messagebox.showerror("SQL Error", err)
            self.fill_table([])
            return

        self.fill_table(rows)

    def on_safe(self):
        user_text = self.entry.get()
        rows, sql, err = safe_search_by_name(user_text)
        self.set_sql_text("SQL-запит: " + sql)

        if err:
            messagebox.showerror("SQL Error", err)
            self.fill_table([])
            return

        self.fill_table(rows)


if __name__ == "__main__":
    build_database()
    root = tk.Tk()
    app = SQLiDemoUI(root)
    root.mainloop()
