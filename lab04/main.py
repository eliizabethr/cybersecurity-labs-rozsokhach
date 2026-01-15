import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import random
import hashlib
import json
import os
import sys

sys.set_int_max_str_digits(10000)


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0


def is_probable_prime(n, rounds=5):
    if n < 2 or n % 2 == 0:
        return n == 2
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits=256):
    while True:
        num = random.getrandbits(bits) | (1 << bits - 1) | 1
        if is_probable_prime(num):
            return num


def generate_rsa_keys(name, dob, secret):
    seed = int(hashlib.sha256(f"{name}{dob}{secret}".encode()).hexdigest(), 16)
    random.seed(seed)

    p = generate_prime()
    q = generate_prime()
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    if gcd(e, phi) != 1:
        e = 3
        while gcd(e, phi) != 1:
            e += 2

    d = modinv(e, phi)

    pub = {"e": e, "n": n}
    priv = {"d": d, "n": n}

    return json.dumps(pub).encode(), json.dumps(priv).encode()


def sign_document(path, priv_key_bytes):
    priv = json.loads(priv_key_bytes)
    d, n = priv["d"], priv["n"]

    with open(path, "rb") as f:
        data = f.read()

    h = hashlib.new("sha512")
    h.update(data)
    hash_int = int(h.hexdigest(), 16) % n

    signature = pow(hash_int, d, n)
    sig_path = path + ".sig"

    with open(sig_path, "w") as f:
        f.write(hex(signature))

    return sig_path


def verify_document(path, sig_path, pub_key_bytes):
    pub = json.loads(pub_key_bytes)
    e, n = pub["e"], pub["n"]

    with open(sig_path, "r") as f:
        signature = int(f.read(), 16)

    decrypted_hash = pow(signature, e, n)

    with open(path, "rb") as f:
        data = f.read()

    h = hashlib.new("sha512")
    h.update(data)
    
    if int(h.hexdigest(), 16) % n == decrypted_hash:
        return True

    return False


def load_public_key():
    if os.path.exists("public.pem"):
        return open("public.pem", "rb").read()
    return None


def load_private_key():
    if os.path.exists("private.pem"):
        return open("private.pem", "rb").read()
    return None


class DigitalSignatureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Електронний цифровий підпис")
        self.root.geometry("640x320")

        self.pub = load_public_key()
        self.priv = load_private_key()

        tabs = ttk.Notebook(root)
        self.tab_gen = ttk.Frame(tabs)
        self.tab_sign = ttk.Frame(tabs)
        self.tab_verify = ttk.Frame(tabs)

        tabs.add(self.tab_gen, text="Генерація ключів")
        tabs.add(self.tab_sign, text="Підпис файлу")
        tabs.add(self.tab_verify, text="Перевірка підпису")
        tabs.pack(expand=True, fill="both")

        self._build_gen_tab()
        self._build_sign_tab()
        self._build_verify_tab()

    def _build_gen_tab(self):
        frame = ttk.LabelFrame(self.tab_gen, text="Персональні дані", padding=15)
        frame.pack(fill="x", padx=20, pady=20)

        ttk.Label(frame, text="ПІБ:").grid(row=0, column=0, sticky="w")
        self.ent_name = ttk.Entry(frame, width=40)
        self.ent_name.grid(row=0, column=1)

        ttk.Label(frame, text="Дата народження:").grid(row=1, column=0, sticky="w")
        self.ent_dob = ttk.Entry(frame, width=40)
        self.ent_dob.grid(row=1, column=1)

        ttk.Label(frame, text="Секретне слово:").grid(row=2, column=0, sticky="w")
        self.ent_secret = ttk.Entry(frame, width=40, show="*")
        self.ent_secret.grid(row=2, column=1)

        ttk.Button(self.tab_gen, text="Згенерувати ключі", command=self.generate_keys).pack(pady=10)
        self.lbl_gen = ttk.Label(self.tab_gen)
        self.lbl_gen.pack()

    def generate_keys(self):
        if not all((self.ent_name.get(), self.ent_dob.get(), self.ent_secret.get())):
            messagebox.showerror("Помилка", "Заповніть усі поля")
            return

        self.lbl_gen.config(text="Генерація ключів, зачекайте...", foreground="blue")
        self.root.update()

        self.pub, self.priv = generate_rsa_keys(
            self.ent_name.get(),
            self.ent_dob.get(),
            self.ent_secret.get()
        )

        open("public.pem", "wb").write(self.pub)
        open("private.pem", "wb").write(self.priv)

        self.lbl_gen.config(text="Ключі згенеровано успішно", foreground="green")

    def _build_sign_tab(self):
        frame = ttk.LabelFrame(self.tab_sign, text="Підпис", padding=15)
        frame.pack(fill="x", padx=20, pady=20)

        ttk.Button(frame, text="Обрати файл", command=self.choose_file_to_sign).pack(fill="x")
        self.lbl_sign_file = ttk.Label(frame, text="Файл не обрано")
        self.lbl_sign_file.pack()

        ttk.Button(frame, text="Підписати", command=self.sign).pack(pady=10)

    def choose_file_to_sign(self):
        self.sign_path = filedialog.askopenfilename()
        if self.sign_path:
            self.lbl_sign_file.config(text=os.path.basename(self.sign_path))

    def sign(self):
        priv = load_private_key()
        if not priv:
            messagebox.showwarning("Увага", "Приватний ключ не знайдено")
            return
        sig = sign_document(self.sign_path, self.priv)
        messagebox.showinfo("Готово", f"Підпис створено:\n{os.path.basename(sig)}")

    def _build_verify_tab(self):
        frame = ttk.LabelFrame(self.tab_verify, text="Перевірка", padding=15)
        frame.pack(fill="x", padx=20, pady=20)

        ttk.Button(frame, text="Файл", command=self.choose_verify_file).pack(fill="x")
        self.lbl_v_file = ttk.Label(frame, text="Файл не обрано")
        self.lbl_v_file.pack()

        ttk.Button(frame, text="Підпис (.sig)", command=self.choose_verify_sig).pack(fill="x")
        self.lbl_v_sig = ttk.Label(frame, text="Підпис не обрано")
        self.lbl_v_sig.pack()

        ttk.Button(frame, text="Перевірити", command=self.verify).pack(pady=10)
        self.lbl_result = ttk.Label(self.tab_verify, font=("Arial", 14, "bold"))
        self.lbl_result.pack()

    def choose_verify_file(self):
        self.v_file = filedialog.askopenfilename()
        if self.v_file:
            self.lbl_v_file.config(text=os.path.basename(self.v_file))

    def choose_verify_sig(self):
        self.v_sig = filedialog.askopenfilename(filetypes=[("Signature", "*.sig")])
        if self.v_sig:
            self.lbl_v_sig.config(text=os.path.basename(self.v_sig))

    def verify(self):
        pub = load_public_key()
        if not pub:
            messagebox.showwarning("Увага", "Публічний ключ не знайдено")
            return

        ok = verify_document(self.v_file, self.v_sig, self.pub)
        if ok:
            self.lbl_result.config(text="ПІДПИС ДІЙСНИЙ", foreground="green")
        else:
            self.lbl_result.config(text="ПІДПИС НЕДІЙСНИЙ", foreground="red")


if __name__ == "__main__":
    root = tk.Tk()
    DigitalSignatureGUI(root)
    root.mainloop()
