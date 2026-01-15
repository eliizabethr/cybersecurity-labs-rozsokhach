from PIL import Image
import os

EOF_MARKER = "[[EOF]]"

def bytes_to_bits(data: bytes) -> str:
    return "".join(f"{b:08b}" for b in data)

def bits_to_bytes(bits: str) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        if len(chunk) == 8:
            out.append(int(chunk, 2))
    return bytes(out)

def hide_message(image_path, message, output_path):
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()
    w, h = img.size

    message += EOF_MARKER
    data = message.encode("utf-8")
    bits = bytes_to_bits(data)

    if len(bits) > w * h * 3:
        print("[Помилка] Повідомлення занадто велике")
        return

    idx = 0
    for y in range(h):
        for x in range(w):
            r, g, b = pixels[x, y]
            new_pixel = []
            for channel in (r, g, b):
                if idx < len(bits):
                    channel = (channel & ~1) | int(bits[idx])
                    idx += 1
                new_pixel.append(channel)
            pixels[x, y] = tuple(new_pixel)
            if idx >= len(bits):
                img.save(output_path, "PNG")
                print(f"[Успіх] Повідомлення приховано у {output_path}")
                return

def extract_message(image_path):
    img = Image.open(image_path).convert("RGB")
    pixels = img.load()
    w, h = img.size

    bits = ""
    for y in range(h):
        for x in range(w):
            for channel in pixels[x, y]:
                bits += str(channel & 1)

                if len(bits) % 8 == 0:
                    data = bits_to_bytes(bits)
                    try:
                        text = data.decode("utf-8")
                        if text.endswith(EOF_MARKER):
                            return text[:-len(EOF_MARKER)]
                    except UnicodeDecodeError:
                        pass
    return None

def main():
    while True:
        print("\n=== LSB-СТЕГАНОГРАФІЯ ===")
        print("1. Приховати повідомлення")
        print("2. Витягти повідомлення")
        print("3. Вийти")

        choice = input("Ваш вибір: ")

        if choice == "1":
            img = input("Шлях до зображення: ")
            msg = input("Секретне повідомлення: ")
            out = input("Вихідний файл (ENTER → encoded.png): ") or "encoded.png"

            if os.path.abspath(img) == os.path.abspath(out):
                print("[Помилка] Не можна перезаписати оригінал")
                continue

            hide_message(img, msg, out)

        elif choice == "2":
            img = input("Шлях до зображення: ")
            msg = extract_message(img)

            if msg:
                print("\n--- ВИТЯГНУТЕ ПОВІДОМЛЕННЯ ---")
                print(msg)
            else:
                print("Повідомлення не знайдено")

        elif choice == "3":
            print("Завершення роботи.")
            break

        else:
            print("Невірний вибір.")


if __name__ == "__main__":
    main()
