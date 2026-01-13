from datetime import datetime
import string

def cyrillic_to_latin(text: str) -> str:
    CYR_TO_LAT = {
        'а': 'a', 'б': 'b', 'в': 'v', 'г': 'h', 'ґ': 'g', 'д': 'd', 'е': 'e', 'є': 'ie',
        'ж': 'zh', 'з': 'z', 'и': 'y', 'і': 'i', 'ї': 'i', 'й': 'i', 'к': 'k', 'л': 'l',
        'м': 'm', 'н': 'n', 'о': 'o', 'п': 'p', 'р': 'r', 'с': 's', 'т': 't', 'у': 'u',
        'ф': 'f', 'х': 'kh', 'ц': 'ts', 'ч': 'ch', 'ш': 'sh', 'щ': 'shch',
        'ь': '', 'ю': 'iu', 'я': 'ia'
    }
    return "".join(CYR_TO_LAT.get(ch, ch) for ch in text.lower())


def collect_sensitive_parts(first_name: str, last_name: str, birth_date: str) -> set:
    parts = set()

    for value in (first_name, last_name):
        if value:
            parts.update({value.lower(), cyrillic_to_latin(value)})

    if birth_date:
        try:
            date = datetime.strptime(birth_date, "%d.%m.%Y")
            parts.update({
                str(date.day),
                str(date.month),
                str(date.year),
                f"{date.day:02d}{date.month:02d}",
                str(date.year)[-2:]
            })
        except ValueError:
            pass

    return {p for p in parts if len(p) > 1}


def password_audit(pwd: str, forbidden: set) -> dict:
    report = {
        "value": 1,
        "warnings": [],
        "tips": [],
        "personal_hits": []
    }

    # --- ДОВЖИНА ---
    size = len(pwd)
    if size >= 12:
        report["value"] += 5
    elif size >= 8:
        report["value"] += 3
    else:
        report["warnings"].append("Пароль занадто короткий")

    # --- КЛАСИ СИМВОЛІВ ---
    checks = {
        "малі літери": any(ch.islower() for ch in pwd),
        "великі літери": any(ch.isupper() for ch in pwd),
        "цифри": any(ch.isdigit() for ch in pwd),
        "спецсимволи": any(ch in set(string.punctuation) for ch in pwd)
    }

    for label, ok in checks.items():
        if ok:
            report["value"] += 1
        else:
            report["warnings"].append(f"Відсутні {label}")

    # --- ПРОСТІ ПАТЕРНИ ---
    low = pwd.lower()
    if any(seq in low for seq in ("123", "abc", "qwe")):
        report["warnings"].append("Присутні прості послідовності")
        report["value"] -= 2

    # --- ПЕРСОНАЛЬНІ ДАНІ ---
    for token in forbidden:
        if token in low:
            report["personal_hits"].append(token)

    if report["personal_hits"]:
        report["warnings"].append("Пароль містить персональні дані")
        report["tips"].append("Не використовуйте ПІБ або дату народження у паролі")
        report["value"] -= 5

    # --- РЕКОМЕНДАЦІЇ ---
    if size < 12:
        report["tips"].append("Збільште довжину пароля до 12 символів")

    if not report["warnings"]:
        report["tips"].append("Пароль виглядає надійним")

    report["value"] = max(1, min(10, report["value"]))
    return report


def main():
    print("=== ПЕРЕВІРКА НАДІЙНОСТІ ПАРОЛЯ ===\n")
    
    print("Для початку введіть персональні дані.")

    first_name = input("Ім'я: ")
    last_name = input("Прізвище: ")
    birth_date = input("Дата народження (ДД.ММ.РРРР): ")

    black_list = collect_sensitive_parts(first_name, last_name, birth_date)
    
    print("\nТепер проаналізуємо пароль.")

    while True:
        pwd = input("Введіть пароль (введіть 'exit' для виходу): ")
        if pwd.lower() == "exit":
            print("Завершення роботи.")
            break

        if not pwd:
            print("Пароль не може бути порожнім\n")
            continue

        result = password_audit(pwd, black_list)

        print("\n--- РЕЗУЛЬТАТ ---")
        level = (
            "Дуже сильний" if result["value"] >= 8 else
            "Середній" if result["value"] >= 5 else
            "Слабкий"
        )

        print(f"Оцінка: {result['value']}/10 ({level})")

        if result["personal_hits"]:
            print("! Персональні збіги:", ", ".join(set(result["personal_hits"])))

        if result["warnings"]:
            print("\nПроблеми:")
            for w in sorted(set(result["warnings"])):
                print(f" - {w}")

        if result["tips"]:
            print("\nРекомендації:")
            for t in sorted(set(result["tips"])):
                print(f" - {t}")
        print()


if __name__ == "__main__":
    main()
