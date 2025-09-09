"""
Модуль для 2FA авторизації через email
"""
import json
import os
import smtplib
import secrets
import string
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from logger import logger


class Email2FA:
    """Клас для управління 2FA через email"""
    
    def __init__(self, codes_file: str = "pending_codes.json"):
        """
        Ініціалізація 2FA менеджера
        
        Args:
            codes_file: Шлях до файлу з кодами підтвердження
        """
        self.codes_file = codes_file
        self.codes_data = self._load_codes()
        self.code_length = 6
        self.code_expiry_minutes = 60
        self.max_attempts = 3
    
    def _load_codes(self) -> Dict[str, Any]:
        """Завантаження збережених кодів"""
        if os.path.exists(self.codes_file):
            try:
                with open(self.codes_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.log_error(f"Помилка завантаження файлу кодів: {e}")
                return {"codes": {}}
        return {"codes": {}}
    
    def _save_codes(self) -> None:
        """Збереження кодів"""
        try:
            with open(self.codes_file, 'w', encoding='utf-8') as f:
                json.dump(self.codes_data, f, ensure_ascii=False, indent=2)
        except IOError as e:
            logger.log_error(f"Помилка збереження файлу кодів: {e}")
    
    def _generate_code(self) -> str:
        """Генерація 6-значного коду"""
        return ''.join(secrets.choice(string.digits) for _ in range(self.code_length))
    
    def _is_code_expired(self, expires_at: str) -> bool:
        """Перевірка чи код прострочений"""
        try:
            expiry_time = datetime.strptime(expires_at, "%Y-%m-%d %H:%M:%S")
            return datetime.now() > expiry_time
        except ValueError:
            return True
    
    def _cleanup_expired_codes(self) -> None:
        """Видалення прострочених кодів"""
        current_time = datetime.now()
        expired_users = []
        
        for user_id, code_info in self.codes_data["codes"].items():
            if self._is_code_expired(code_info["expires_at"]):
                expired_users.append(user_id)
        
        for user_id in expired_users:
            del self.codes_data["codes"][user_id]
            logger.log_info(f"Видалено прострочений код для користувача {user_id}")
        
        if expired_users:
            self._save_codes()
    
    def send_verification_code(self, user_id: int, username: str, admin_email: str, 
                             smtp_server: str, smtp_port: int, smtp_username: str, 
                             smtp_password: str) -> Optional[str]:
        """
        Відправка коду підтвердження на email адміна
        
        Args:
            user_id: ID користувача
            username: Ім'я користувача
            admin_email: Email адміна
            smtp_server: SMTP сервер
            smtp_port: SMTP порт
            smtp_username: SMTP логін
            smtp_password: SMTP пароль
            
        Returns:
            Згенерований код або None при помилці
        """
        # Очищуємо прострочені коди
        self._cleanup_expired_codes()
        
        # Генеруємо новий код
        code = self._generate_code()
        expires_at = datetime.now() + timedelta(minutes=self.code_expiry_minutes)
        
        # Зберігаємо код
        self.codes_data["codes"][str(user_id)] = {
            "code": code,
            "expires_at": expires_at.strftime("%Y-%m-%d %H:%M:%S"),
            "attempts": 0,
            "max_attempts": self.max_attempts,
            "username": username
        }
        self._save_codes()
        
        # Створюємо email
        subject = f"Код підтвердження для KeePass Bot - {username}"
        body = f"""
Код підтвердження для доступу до KeePass Bot

Користувач: @{username}
ID: {user_id}
Код: {code}

Код дійсний протягом {self.code_expiry_minutes} хвилин.

Якщо ви не запитували цей код, проігноруйте це повідомлення.
        """.strip()
        
        try:
            # Створюємо повідомлення
            msg = MIMEMultipart()
            msg['From'] = smtp_username
            msg['To'] = admin_email
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain', 'utf-8'))
            
            # Відправляємо email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(smtp_username, smtp_password)
                server.send_message(msg)
            
            logger.log_info(f"Код підтвердження відправлено на {admin_email} для користувача {user_id}")
            return code
            
        except Exception as e:
            logger.log_error(f"Помилка відправки email: {e}")
            # Видаляємо код при помилці відправки
            if str(user_id) in self.codes_data["codes"]:
                del self.codes_data["codes"][str(user_id)]
                self._save_codes()
            return None
    
    def verify_code(self, user_id: int, input_code: str) -> Dict[str, Any]:
        """
        Перевірка введеного коду
        
        Args:
            user_id: ID користувача
            input_code: Введений код
            
        Returns:
            Словник з результатом перевірки
        """
        user_id_str = str(user_id)
        
        if user_id_str not in self.codes_data["codes"]:
            return {
                "success": False,
                "message": "Код не знайдено. Спробуйте спочатку ввести пін-код.",
                "can_retry": False
            }
        
        code_info = self.codes_data["codes"][user_id_str]
        
        # Перевіряємо чи код не прострочений
        if self._is_code_expired(code_info["expires_at"]):
            del self.codes_data["codes"][user_id_str]
            self._save_codes()
            return {
                "success": False,
                "message": "Код прострочений. Спробуйте спочатку ввести пін-код.",
                "can_retry": False
            }
        
        # Перевіряємо кількість спроб
        if code_info["attempts"] >= code_info["max_attempts"]:
            del self.codes_data["codes"][user_id_str]
            self._save_codes()
            logger.log_error(f"Перевищено кількість спроб для користувача {user_id}")
            return {
                "success": False,
                "message": "Перевищено кількість спроб. Доступ заблоковано.",
                "can_retry": False
            }
        
        # Перевіряємо код
        if input_code == code_info["code"]:
            # Код правильний
            del self.codes_data["codes"][user_id_str]
            self._save_codes()
            logger.log_info(f"Код підтвердження успішно перевірено для користувача {user_id}")
            return {
                "success": True,
                "message": "Код підтверджено!",
                "can_retry": False
            }
        else:
            # Код невірний
            code_info["attempts"] += 1
            remaining_attempts = code_info["max_attempts"] - code_info["attempts"]
            self._save_codes()
            
            logger.log_error(f"Невірний код для користувача {user_id}. Залишилось спроб: {remaining_attempts}")
            
            if remaining_attempts > 0:
                return {
                    "success": False,
                    "message": f"Невірний код. Залишилось спроб: {remaining_attempts}",
                    "can_retry": True
                }
            else:
                del self.codes_data["codes"][user_id_str]
                self._save_codes()
                return {
                    "success": False,
                    "message": "Перевищено кількість спроб. Доступ заблоковано.",
                    "can_retry": False
                }
    
    def resend_code(self, user_id: int, username: str, admin_email: str,
                   smtp_server: str, smtp_port: int, smtp_username: str, 
                   smtp_password: str) -> Optional[str]:
        """
        Повторна відправка коду
        
        Args:
            user_id: ID користувача
            username: Ім'я користувача
            admin_email: Email адміна
            smtp_server: SMTP сервер
            smtp_port: SMTP порт
            smtp_username: SMTP логін
            smtp_password: SMTP пароль
            
        Returns:
            Новий код або None при помилці
        """
        # Видаляємо старий код
        if str(user_id) in self.codes_data["codes"]:
            del self.codes_data["codes"][str(user_id)]
            self._save_codes()
        
        # Відправляємо новий код
        return self.send_verification_code(
            user_id, username, admin_email, 
            smtp_server, smtp_port, smtp_username, smtp_password
        )


# Глобальний екземпляр 2FA менеджера
email_2fa = Email2FA()
