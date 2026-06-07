import requests
# Убедитесь, что порт совпадает с тем, что пишет Uvicorn
API_URL = "http://127.0.0.1:8080/api/v1/analyze"

scenarios = [
    {"payload": "<script>alert('Hacked')</script>", "ip": "192.168.5.10", "type": "XSS Attack"},
    {"payload": "UNION SELECT password FROM admins", "ip": "10.0.0.66", "type": "SQL Injection Attack"},
    {"payload": "/login", "ip": "192.168.1.5", "type": "Safe User"},
]

print("--- WebShield AI Debugging Test ---")

for s in scenarios:
    data = {
        "timestamp": "2023-10-27T10:00:00",
        "source_ip": s["ip"],
        "request_url": API_URL,
        "user_agent": "Mozilla/5.0",
        "method": "GET",
        "payload": s["payload"]
    }

    try:
        response = requests.post(API_URL, json=data)

        # Если сервер ответил не 200 (ОК)
        if response.status_code != 200:
            print(f"\n[!] Ошибка сервера! Код: {response.status_code}")
            print(f"Ответ сервера (первые 100 символов): {response.text[:100]}")
            continue

        res_json = response.json()
        print(f"\nУспех! Цель: {s['type']}")
        print(f"Результат: {res_json['status']} (Тип: {res_json['threat_type']})")

    except Exception as e:
        print(f"\n[!] Ошибка соединения: {e}")

#.strftime('%Y-%m-%d %H:%M:%S')