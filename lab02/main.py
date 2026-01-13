UKR_ALPHABET = "абвгґдеєжзиіїйклмнопрстуфхцчшщьюя"
ALPHABET_LEN = len(UKR_ALPHABET)

def encrypt_caesar(text: str, shift: int) -> str:
    result = ""
    for ch in text.lower():
        if ch in UKR_ALPHABET:
            idx = UKR_ALPHABET.index(ch)
            result += UKR_ALPHABET[(idx + shift) % ALPHABET_LEN]
        else:
            result += ch
    return result

def decrypt_caesar(text: str, shift: int) -> str:
    return encrypt_caesar(text, -shift)

def encrypt_vigenere(text: str, key: str) -> str:
    result = ""
    key = key.lower()
    k = 0

    for ch in text.lower():
        if ch in UKR_ALPHABET:
            t = UKR_ALPHABET.index(ch)
            s = UKR_ALPHABET.index(key[k % len(key)])
            result += UKR_ALPHABET[(t + s) % ALPHABET_LEN]
            k += 1
        else:
            result += ch
    return result

def decrypt_vigenere(text: str, key: str) -> str:
    result = ""
    key = key.lower()
    k = 0

    for ch in text.lower():
        if ch in UKR_ALPHABET:
            t = UKR_ALPHABET.index(ch)
            s = UKR_ALPHABET.index(key[k % len(key)])
            result += UKR_ALPHABET[(t - s) % ALPHABET_LEN]
            k += 1
        else:
            result += ch
    return result

def caesar_key_from_date(date: str) -> int:
    digits = [int(d) for d in date if d.isdigit()]
    return sum(digits) % ALPHABET_LEN or 1

def vigenere_key_from_surname(surname: str) -> str:
    key = "".join(ch for ch in surname.lower() if ch in UKR_ALPHABET)
    return key if key else "КЛЮЧ"

def print_comparison(original, caesar, vigenere):
    print("\n--- ПОРІВНЯЛЬНИЙ АНАЛІЗ ---")
    print(f"Оригінал: {original}")
    print(f"Цезар:    {caesar}")
    print(f"Віженер:  {vigenere}\n")

    print("Висновки:")
    print("- Шифр Цезаря зберігає структуру тексту, тому є простим і менш надійним.")
    print("- Шифр Віженера виглядає більш випадковим та забезпечує кращий рівень захисту.")

def main():
    print("=== ЗАХИСТ ОСОБИСТИХ ПОВІДОМЛЕНЬ ===\n")

    surname = input("Введіть прізвище: ")
    date = input("Введіть дату народження (ДД.ММ.РРРР): ")
    text = input("Введіть текст для шифрування: ")

    if not text:
        text = "Безпека програм та даних"
        print(f"(Використано приклад: '{text}')")

    text = text.lower()

    caesar_key = caesar_key_from_date(date)
    vigenere_key = vigenere_key_from_surname(surname)

    print("\nЗгенеровані ключі:")
    print(f"- Цезар: зсув {caesar_key}")
    print(f"- Віженер: '{vigenere_key}'")

    caesar_cipher = encrypt_caesar(text, caesar_key)
    vigenere_cipher = encrypt_vigenere(text, vigenere_key)
    
    print("\nШифрування:")
    print("Цезар:", caesar_cipher)
    print("Віженер:", vigenere_cipher)

    print("\nРозшифрування:")
    print("Цезар:", decrypt_caesar(caesar_cipher, caesar_key))
    print("Віженер:", decrypt_vigenere(vigenere_cipher, vigenere_key))

    print_comparison(text, caesar_cipher, vigenere_cipher)

if __name__ == "__main__":
    main()
