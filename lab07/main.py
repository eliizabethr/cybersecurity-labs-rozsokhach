import os
import sys
import csv
import time
import hashlib
import random
import struct
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from PIL import Image

# Дозволяємо працювати з великими числами (RSA)
sys.set_int_max_str_digits(10000)


def sha256_int(data: bytes) -> int:
    return int(hashlib.sha256(data).hexdigest(), 16)


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    k = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % k]
    return bytes(out)


def kdf_from_password(password: str) -> bytes:
    # 256-bit ключ для XOR (демо-симетричний ключ)
    return hashlib.sha256(password.encode("utf-8")).digest()


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a


def modinv(a: int, m: int) -> int:
    # розширений Евклід (ітеративно)
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        q = r // new_r
        t, new_t = new_t, t - q * new_t
        r, new_r = new_r, r - q * new_r
    if r != 1:
        raise ValueError("No modular inverse")
    return t % m


def is_probable_prime(n: int, rounds: int, rng: random.Random) -> bool:
    if n < 2:
        return False
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for p in small_primes:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Miller–Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        a = rng.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        witness = True
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                witness = False
                break
        if witness:
            return False
    return True


def generate_prime(bits: int, rng: random.Random) -> int:
    while True:
        candidate = rng.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1  # старший біт + непарність
        if is_probable_prime(candidate, rounds=6, rng=rng):
            return candidate


def rsa_keys_from_password(password: str, bits: int = 256):
    seed = int(hashlib.sha256(password.encode("utf-8")).hexdigest(), 16)
    rng = random.Random(seed)

    p = generate_prime(bits, rng)
    q = generate_prime(bits, rng)
    while q == p:
        q = generate_prime(bits, rng)

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
    return pub, priv


def rsa_sign(data: bytes, priv: dict) -> int:
    n = priv["n"]
    h = sha256_int(data) % n
    return pow(h, priv["d"], n)


def rsa_verify(data: bytes, signature: int, pub: dict) -> bool:
    n = pub["n"]
    expected = sha256_int(data) % n
    got = pow(signature, pub["e"], n)
    return expected == got


def _bytes_to_bits(payload: bytes) -> str:
    return "".join(f"{b:08b}" for b in payload)


def hide_payload_lsb(carrier_png: str, payload: bytes, output_png: str):
    img = Image.open(carrier_png).convert("RGB")
    px = img.load()
    w, h = img.size

    header = struct.pack(">I", len(payload))
    full = header + payload
    bits = _bytes_to_bits(full)
    need = len(bits)
    capacity = w * h * 3
    if need > capacity:
        raise ValueError(f"Зображення замале: потрібно {need} біт, доступно {capacity} біт.")

    idx = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            channels = [r, g, b]
            for ci in range(3):
                if idx >= need:
                    break
                bit = int(bits[idx])
                channels[ci] = (channels[ci] & ~1) | bit
                idx += 1
            px[x, y] = tuple(channels)
            if idx >= need:
                img.save(output_png, "PNG")
                return

    img.save(output_png, "PNG")


def extract_payload_lsb(stego_png: str) -> bytes:
    img = Image.open(stego_png).convert("RGB")
    px = img.load()
    w, h = img.size

    def bit_stream():
        for y in range(h):
            for x in range(w):
                r, g, b = px[x, y]
                yield r & 1
                yield g & 1
                yield b & 1

    stream = bit_stream()

    size_bits = 0
    for _ in range(32):
        size_bits = (size_bits << 1) | next(stream)
    size = size_bits

    data = bytearray()
    for _ in range(size):
        val = 0
        for __ in range(8):
            val = (val << 1) | next(stream)
        data.append(val)

    return bytes(data)


def pack_with_extension(file_path: str) -> bytes:
    ext = os.path.splitext(file_path)[1].encode("utf-8")  # b'.pdf'
    if len(ext) > 255:
        raise ValueError("Занадто довге розширення файлу.")
    ext_len = bytes([len(ext)])
    with open(file_path, "rb") as f:
        content = f.read()
    return ext_len + ext + content


def unpack_with_extension(meta: bytes):
    if len(meta) < 1:
        raise ValueError("Пакет пошкоджено (нема ext_len).")
    ext_len = meta[0]
    if len(meta) < 1 + ext_len:
        raise ValueError("Пакет пошкоджено (нема ext).")
    ext = meta[1:1 + ext_len].decode("utf-8")
    content = meta[1 + ext_len:]
    return ext, content


def make_signed_package(meta: bytes, priv: dict) -> bytes:
    sig_int = rsa_sign(meta, priv)
    sig_bytes = sig_int.to_bytes((sig_int.bit_length() + 7) // 8 or 1, "big")
    sig_len = struct.pack(">I", len(sig_bytes))
    return sig_len + sig_bytes + meta


def split_signed_package(pkg: bytes):
    if len(pkg) < 4:
        raise ValueError("Пакет пошкоджено (нема sig_len).")
    sig_len = struct.unpack(">I", pkg[:4])[0]
    if len(pkg) < 4 + sig_len:
        raise ValueError("Пакет пошкоджено (нема signature).")
    sig_bytes = pkg[4:4 + sig_len]
    meta = pkg[4 + sig_len:]
    sig_int = int.from_bytes(sig_bytes, "big")
    return sig_int, meta


class MetricsLog:
    def __init__(self):
        self.rows = []

    def add(self, stage: str, ms: float, size_bytes: int):
        self.rows.append({
            "Stage": stage,
            "TimeMs": f"{ms:.2f}",
            "SizeBytes": str(size_bytes)
        })

    def export_csv(self, path: str):
        if not self.rows:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.DictWriter(f, fieldnames=["Stage", "TimeMs", "SizeBytes"])
            w.writeheader()
            w.writerows(self.rows)

class SecurePipelineApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("Комплексна система захисту даних (RSA + XOR + LSB)")
        root.geometry("800x420")

        self.doc_path = None
        self.img_path = None
        self.stego_path = None

        self.metrics = MetricsLog()

        nb = ttk.Notebook(root)
        self.tab_protect = ttk.Frame(nb)
        self.tab_restore = ttk.Frame(nb)
        self.tab_stats = ttk.Frame(nb)

        nb.add(self.tab_protect, text="Захист файлу")
        nb.add(self.tab_restore, text="Відновлення файлу")
        nb.add(self.tab_stats, text="Метрики")
        nb.pack(fill="both", expand=True)

        self._build_tab_protect()
        self._build_tab_restore()
        self._build_tab_stats()

    def _build_tab_protect(self):
        box = ttk.LabelFrame(self.tab_protect, text="Послідовний захист файлу", padding=16)
        box.pack(fill="both", expand=True, padx=16, pady=16)

        ttk.Button(box, text="1) Обрати файл (документ)", command=self.pick_document).pack(fill="x", pady=4)
        self.lbl_doc = ttk.Label(box, text="Файл не обрано")
        self.lbl_doc.pack(anchor="w", pady=(0, 8))

        ttk.Button(box, text="2) Обрати зображення-контейнер (PNG/JPG)", command=self.pick_carrier).pack(fill="x", pady=4)
        self.lbl_img = ttk.Label(box, text="Зображення не обрано")
        self.lbl_img.pack(anchor="w", pady=(0, 8))

        ttk.Label(box, text="Пароль (потрібен і для відновлення):").pack(anchor="w")
        self.ent_pwd = ttk.Entry(box, show="*")
        self.ent_pwd.pack(fill="x", pady=6)

        ttk.Button(box, text="🚀 Захистити (підпис → шифр → приховати)", command=self.run_protect).pack(fill="x", pady=(10, 6))

        self.lbl_status = ttk.Label(box, text="", foreground="green", font=("Arial", 10, "bold"))
        self.lbl_status.pack(anchor="w", pady=(10, 0))

    def _build_tab_restore(self):
        box = ttk.LabelFrame(self.tab_restore, text="Відновлення оригіналу", padding=16)
        box.pack(fill="both", expand=True, padx=16, pady=16)

        ttk.Button(box, text="Обрати захищене зображення (PNG)", command=self.pick_stego).pack(fill="x", pady=4)
        self.lbl_stego = ttk.Label(box, text="Файл не обрано")
        self.lbl_stego.pack(anchor="w", pady=(0, 8))

        ttk.Label(box, text="Пароль:").pack(anchor="w")
        self.ent_pwd_restore = ttk.Entry(box, show="*")
        self.ent_pwd_restore.pack(fill="x", pady=6)

        ttk.Button(box, text="🔓 Відновити (витягти → дешифр → перевірити → зберегти)", command=self.run_restore).pack(fill="x", pady=(10, 6))
        self.lbl_restore = ttk.Label(box, text="", font=("Arial", 10, "bold"))
        self.lbl_restore.pack(anchor="w", pady=(10, 0))

    def _build_tab_stats(self):
        cols = ("Stage", "Time", "Size")
        self.tree = ttk.Treeview(self.tab_stats, columns=cols, show="headings", height=10)
        self.tree.heading("Stage", text="Етап")
        self.tree.heading("Time", text="Час")
        self.tree.heading("Size", text="Розмір")

        self.tree.column("Stage")
        self.tree.column("Time", anchor="e")
        self.tree.column("Size", anchor="e")

        self.tree.pack(fill="both", expand=True, padx=12, pady=12)
        ttk.Button(self.tab_stats, text="💾 Експорт CSV", command=self.export_csv).pack(pady=(0, 12))

    def _reset_stats(self):
        self.metrics = MetricsLog()
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _log(self, stage: str, t0: float, size_bytes: int):
        ms = (time.perf_counter() - t0) * 1000.0
        self.metrics.add(stage, ms, size_bytes)
        self.tree.insert("", "end", values=(stage, f"{ms:.2f} ms", f"{size_bytes} bytes"))

    def pick_document(self):
        p = filedialog.askopenfilename()
        if p:
            self.doc_path = p
            self.lbl_doc.config(text=os.path.basename(p))

    def pick_carrier(self):
        p = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if p:
            self.img_path = p
            self.lbl_img.config(text=os.path.basename(p))

    def pick_stego(self):
        p = filedialog.askopenfilename(filetypes=[("PNG images", "*.png")])
        if p:
            self.stego_path = p
            self.lbl_stego.config(text=os.path.basename(p))

    def run_protect(self):
        if not self.doc_path or not self.img_path:
            messagebox.showwarning("Увага", "Оберіть документ і зображення-контейнер.")
            return
        pwd = self.ent_pwd.get()
        if not pwd:
            messagebox.showwarning("Увага", "Введіть пароль.")
            return

        try:
            self._reset_stats()
            
            t0 = time.perf_counter()
            pub, priv = rsa_keys_from_password(pwd, bits=256)
            xkey = kdf_from_password(pwd)
            self._log("Keys (RSA+XOR)", t0, 0)

            t0 = time.perf_counter()
            meta = pack_with_extension(self.doc_path)
            self._log("Pack (+ext)", t0, len(meta))

            t0 = time.perf_counter()
            signed = make_signed_package(meta, priv)
            self._log("Sign (RSA)", t0, len(signed))

            t0 = time.perf_counter()
            encrypted = xor_bytes(signed, xkey)
            self._log("Encrypt (XOR)", t0, len(encrypted))

            t0 = time.perf_counter()
            out_dir = os.path.dirname(self.img_path)
            base = os.path.splitext(os.path.basename(self.img_path))[0]
            out_png = os.path.join(out_dir, f"{base}_protected.png")
            hide_payload_lsb(self.img_path, encrypted, out_png)
            self._log("Hide (LSB)", t0, os.path.getsize(out_png))

            self.lbl_status.config(text=f"Готово: {os.path.basename(out_png)}")
            messagebox.showinfo("Успіх", "Файл захищено та сховано в PNG.")

            return out_png

        except Exception as e:
            messagebox.showerror("Помилка", str(e))
            return None

    def run_restore(self):
        if not self.stego_path:
            messagebox.showwarning("Увага", "Оберіть захищене PNG.")
            return
        pwd = self.ent_pwd_restore.get()
        if not pwd:
            messagebox.showwarning("Увага", "Введіть пароль.")
            return

        try:
            pub, _ = rsa_keys_from_password(pwd, bits=256)
            xkey = kdf_from_password(pwd)

            self._reset_stats()

            t0 = time.perf_counter()
            encrypted = extract_payload_lsb(self.stego_path)
            self._log("Unhide (LSB)", t0, len(encrypted))

            t0 = time.perf_counter()
            signed = xor_bytes(encrypted, xkey)
            self._log("Decrypt (XOR)", t0, len(signed))

            t0 = time.perf_counter()
            sig_int, meta = split_signed_package(signed)
            ok = rsa_verify(meta, sig_int, pub)
            self._log("Verify (RSA)", t0, 0)

            if not ok:
                self.lbl_restore.config(text="Підпис НЕ збігається (невірний пароль або файл змінено)", foreground="red")
                messagebox.showwarning("Перевірка", "Підпис недійсний. Дані не відновлено.")
                return

            ext, content = unpack_with_extension(meta)
            out_dir = os.path.dirname(self.stego_path)
            out_path = os.path.join(out_dir, f"restored_file{ext}")
            with open(out_path, "wb") as f:
                f.write(content)

            self.lbl_restore.config(text=f"Відновлено: {os.path.basename(out_path)}", foreground="green")
            messagebox.showinfo("Успіх", "Файл успішно відновлено.")
        except Exception as e:
            messagebox.showerror("Збій", str(e))

    def export_csv(self):
        if not self.metrics.rows:
            messagebox.showinfo("Експорт", "Немає даних для експорту.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        self.metrics.export_csv(path)
        messagebox.showinfo("Експорт", f"Збережено: {os.path.basename(path)}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurePipelineApp(root)
    root.mainloop()
