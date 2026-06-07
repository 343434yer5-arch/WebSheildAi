import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
import joblib
import os


class ThreatDetector:
    def __init__(self):
        # 1. Сразу создаем атрибут, чтобы ошибки AttributeError больше не было
        self.model = None
        self.model_path = "webshield_model.pkl"
        print(f"[*] Инициализация ThreatDetector. Путь к модели: {os.path.abspath(self.model_path)}")

        try:
            self.train_initial_model()
            print("[+] Инициализация успешно завершена.")
        except Exception as e:
            print(f"[-] КРИТИЧЕСКАЯ ОШИБКА ПРИ ОБУЧЕНИИ: {e}")

    def train_initial_model(self):
        print("[*] Начало обучения ML-модели...")
        data = [
            # SQL Injection
            ("SELECT * FROM users", "SQLI"),
            ("UNION SELECT password FROM admins", "SQLI"),
            ("OR 1=1 --", "SQLI"),
            ("admin' --", "SQLI"),
            ("DROP TABLE users", "SQLI"),

            # XSS
            ("<script>alert(1)</script>", "XSS"),
            ("<img src=x onerror=alert(1)>", "XSS"),
            ("javascript:alert('hack')", "XSS"),

            # Безопасные запросы
            ("/login", "CLEAN"),
            ("/home", "CLEAN"),
            ("/api/v1/user/profile", "CLEAN"),
            ("Hello, how are you?", "CLEAN"),
            ("Search for products", "CLEAN")
        ]
        df = pd.DataFrame(data, columns=["payload", "label"])

        # Создаем конвейер
        pipeline = make_pipeline(
            TfidfVectorizer(analyzer='char', ngram_range=(2, 4)),
            RandomForestClassifier(n_estimators=10)
        )

        # Обучаем
        pipeline.fit(df['payload'], df['label'])

        # ПРИСВАИВАЕМ МОДЕЛЬ
        self.model = pipeline

        # Сохраняем (по желанию, для отладки можно пропустить)
        try:
            joblib.dump(self.model, self.model_path)
            print("[+] Модель сохранена в файл.")
        except Exception as e:
            print(f"[!] Не удалось сохранить модель в файл (но в памяти она есть): {e}")

    def analyze(self, payload: str):
        # Проверка на наличие модели перед использованием
        if self.model is None:
            print("[!] Ошибка: Попытка анализа без обученной модели!")
            return {"type": "MODEL_NOT_READY", "confidence": 0, "is_threat": False}

        try:
            prediction = self.model.predict([payload])[0]
            probs = self.model.predict_proba([payload])[0]
            confidence = max(probs)

            return {
                "type": str(prediction),
                "confidence": round(float(confidence) * 100, 2),
                "is_threat": prediction != "CLEAN"
            }
        except Exception as e:
            print(f"[-] Ошибка при анализе конкретного запроса: {e}")
            return {"type": "ANALYSIS_ERROR", "confidence": 0, "is_threat": False}
