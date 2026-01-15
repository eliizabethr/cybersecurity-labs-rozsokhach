import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import base64
import os

def derive_key(identity: str, dob: str, password: str) -> bytes:
    seed = (identity + dob + password).encode("utf-8")
    return hashlib.sha256(seed).digest()


def xor_transform(data: bytes, key: bytes) -> bytes:
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return bytes(result)


def encrypt_message(text: str, key: bytes) -> str:
    raw = text.encode("utf-8")
    mixed = xor_transform(raw, key)
    return base64.b64encode(mixed).decode("utf-8")


def decrypt_message(encoded: str, key: bytes) -> str:
    try:
        raw = base64.b64decode(encoded)
        plain = xor_transform(raw, key)
        return plain.decode("utf-8")
    except Exception:
        return "[ПОМИЛКА] Неможливо розшифрувати повідомлення"


def save_key(path: str, key: bytes):
    with open(path, "wb") as f:
        f.write(key)


def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


class SecureMailGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Захищена електронна кореспонденція")
        self.root.geometry("600x520")

        self.key = None

        tabs = ttk.Notebook(root)
        self.tab_key = ttk.Frame(tabs)
        self.tab_msg = ttk.Frame(tabs)

        tabs.add(self.tab_key, text="Налаштування ключа")
        tabs.add(self.tab_msg, text="Текстові повідомлення")
        tabs.pack(expand=True, fill="both")

        self.build_key_tab()
        self.build_message_tab()

    def build_key_tab(self):
        frame = ttk.LabelFrame(self.tab_key, text="Генерація ключа", padding=20)
        frame.pack(fill="x", padx=20, pady=20)

        ttk.Label(frame, text="ПІБ або Email:").pack(anchor="w")
        self.ent_id = ttk.Entry(frame)
        self.ent_id.pack(fill="x", pady=5)

        ttk.Label(frame, text="Дата народження:").pack(anchor="w")
        self.ent_dob = ttk.Entry(frame)
        self.ent_dob.pack(fill="x", pady=5)

        ttk.Label(frame, text="Секретна фраза:").pack(anchor="w")
        self.ent_pass = ttk.Entry(frame, show="*")
        self.ent_pass.pack(fill="x", pady=5)

        ttk.Button(frame, text="Згенерувати ключ", command=self.generate_key).pack(pady=10)

        frame2 = ttk.LabelFrame(self.tab_key, text="Файл ключа", padding=15)
        frame2.pack(fill="x", padx=20, pady=10)

        ttk.Button(frame2, text="💾 Зберегти ключ", command=self.save_key).pack(fill="x", pady=5)
        ttk.Button(frame2, text="📂 Завантажити ключ", command=self.load_key).pack(fill="x", pady=5)

        self.lbl_key_status = ttk.Label(self.tab_key, text="Ключ не встановлено", foreground="red")
        self.lbl_key_status.pack(pady=10)

    def generate_key(self):
        if not self.ent_id.get() or not self.ent_pass.get():
            messagebox.showwarning("Увага", "Заповніть ПІБ та секретну фразу")
            return

        self.key = derive_key(
            self.ent_id.get(),
            self.ent_dob.get(),
            self.ent_pass.get()
        )

        self.lbl_key_status.config(text="Ключ згенеровано", foreground="green")
        messagebox.showinfo("Готово", "Ключ успішно створено")

    def save_key(self):
        if not self.key:
            messagebox.showwarning("Увага", "Немає ключа")
            return
        path = filedialog.asksaveasfilename(defaultextension=".key")
        if path:
            save_key(path, self.key)
            messagebox.showinfo("Готово", f"Ключ збережено:\n{os.path.basename(path)}")

    def load_key(self):
        path = filedialog.askopenfilename(filetypes=[("Key file", "*.key")])
        if path:
            self.key = load_key(path)
            self.lbl_key_status.config(text="Ключ завантажено", foreground="blue")
            messagebox.showinfo("Готово", "Ключ успішно завантажено")

    def build_message_tab(self):
        frame = ttk.LabelFrame(self.tab_msg, text="Робота з повідомленнями", padding=20)
        frame.pack(fill="both", expand=True, padx=20, pady=20)

        ttk.Label(frame, text="Вхідний текст / шифр:").pack(anchor="w")
        self.txt_input = tk.Text(frame, height=7)
        self.txt_input.pack(fill="x", pady=5)

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=5)

        ttk.Button(btns, text="🔒 Зашифрувати", command=self.encrypt).pack(side="left", expand=True, fill="x", padx=5)
        ttk.Button(btns, text="🔓 Розшифрувати", command=self.decrypt).pack(side="left", expand=True, fill="x", padx=5)

        ttk.Label(frame, text="Результат:").pack(anchor="w", pady=(10, 0))
        self.txt_output = tk.Text(frame, height=7)
        self.txt_output.pack(fill="x", pady=5)

    def encrypt(self):
        if not self.key:
            messagebox.showwarning("Увага", "Спочатку створіть або завантажте ключ")
            return
        text = self.txt_input.get("1.0", tk.END).strip()
        if text:
            enc = encrypt_message(text, self.key)
            self.txt_output.delete("1.0", tk.END)
            self.txt_output.insert("1.0", enc)

    def decrypt(self):
        if not self.key:
            messagebox.showwarning("Увага", "Немає ключа")
            return
        text = self.txt_input.get("1.0", tk.END).strip()
        if text:
            dec = decrypt_message(text, self.key)
            self.txt_output.delete("1.0", tk.END)
            self.txt_output.insert("1.0", dec)


if __name__ == "__main__":
    root = tk.Tk()
    SecureMailGUI(root)
    root.mainloop()
