"""
Модуль логування для Telegram-бота KeePass
"""
import logging
import os
from datetime import datetime
from typing import Optional


class BotLogger:
    """Клас для логування дій бота"""
    
    def __init__(self, log_file: str = "logs.txt", log_level: str = "INFO"):
        """
        Ініціалізація логера
        
        Args:
            log_file: Шлях до файлу логів
            log_level: Рівень логування
        """
        self.log_file = log_file
        self.logger = logging.getLogger("keepass_bot")
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Налаштування форматування
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Файловий хендлер
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Консольний хендлер
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
    
    def log_access_request(self, user_id: int, username: str) -> None:
        """Логування запиту на доступ"""
        self.logger.info(f"UserID: {user_id} | Username: @{username} | Дія: Запит на доступ")
    
    def log_access_granted(self, user_id: int, username: str) -> None:
        """Логування надання доступу"""
        self.logger.info(f"UserID: {user_id} | Username: @{username} | Дія: Доступ надано")
    
    def log_access_denied(self, user_id: int, username: str) -> None:
        """Логування відмови в доступі"""
        self.logger.info(f"UserID: {user_id} | Username: @{username} | Дія: Доступ відхилено")
    
    def log_search(self, user_id: int, query: str, results_count: int) -> None:
        """Логування пошуку"""
        self.logger.info(f"UserID: {user_id} | Пошук: {query} | Результатів: {results_count}")
    
    def log_password_view(self, user_id: int, entry_title: str) -> None:
        """Логування перегляду пароля"""
        self.logger.info(f"UserID: {user_id} | Перегляд пароля: {entry_title}")
    
    def log_revoke_access(self, admin_id: int, revoked_user_id: int) -> None:
        """Логування відкликання доступу"""
        self.logger.info(f"AdminID: {admin_id} | Відкликано доступ для UserID: {revoked_user_id}")
    
    def log_admin_approve(self, admin_id: int, approved_user_id: int, username: str) -> None:
        """Логування схвалення користувача адміном"""
        self.logger.info(f"AdminID: {admin_id} | СХВАЛЕНО доступ для UserID: {approved_user_id} (@{username})")
    
    def log_admin_deny(self, admin_id: int, denied_user_id: int, username: str) -> None:
        """Логування відхилення користувача адміном"""
        self.logger.info(f"AdminID: {admin_id} | ВІДХИЛЕНО доступ для UserID: {denied_user_id} (@{username})")
    
    def log_admin_remove_user(self, admin_id: int, removed_user_id: int, username: str) -> None:
        """Логування видалення користувача адміном"""
        self.logger.info(f"AdminID: {admin_id} | ВИДАЛЕНО користувача UserID: {removed_user_id} (@{username})")
    
    def log_admin_panel_access(self, admin_id: int) -> None:
        """Логування доступу до адмін панелі"""
        self.logger.info(f"AdminID: {admin_id} | ДОСТУП до адмін панелі")
    
    def log_intrusion_attempt(self, user_id: int, attempt_type: str, details: str = "") -> None:
        """Логування спроб вторгнення"""
        self.logger.warning(f"СПРОБА ВТОРГНЕННЯ | UserID: {user_id} | Тип: {attempt_type} | Деталі: {details}")
    
    def log_rate_limit_exceeded(self, user_id: int, limit_type: str, attempts: int, max_attempts: int) -> None:
        """Логування перевищення rate limit"""
        self.logger.warning(f"RATE LIMIT | UserID: {user_id} | Тип: {limit_type} | Спроби: {attempts}/{max_attempts}")
    
    def log_invalid_pin(self, user_id: int, attempts: int, max_attempts: int) -> None:
        """Логування невірного пін-коду"""
        self.logger.warning(f"НЕВІРНИЙ ПІН | UserID: {user_id} | Спроби: {attempts}/{max_attempts}")
    
    def log_invalid_2fa(self, user_id: int, attempts: int, max_attempts: int) -> None:
        """Логування невірного 2FA коду"""
        self.logger.warning(f"НЕВІРНИЙ 2FA | UserID: {user_id} | Спроби: {attempts}/{max_attempts}")
    
    def log_pin_lockout(self, user_id: int, lockout_duration: int) -> None:
        """Логування блокування через пін-код"""
        self.logger.warning(f"БЛОКУВАННЯ ПІН | UserID: {user_id} | Тривалість: {lockout_duration}с")
    
    def log_2fa_lockout(self, user_id: int, lockout_duration: int) -> None:
        """Логування блокування через 2FA"""
        self.logger.warning(f"БЛОКУВАННЯ 2FA | UserID: {user_id} | Тривалість: {lockout_duration}с")
    
    def log_unauthorized_access_attempt(self, user_id: int, command: str) -> None:
        """Логування спроб неавторизованого доступу"""
        self.logger.warning(f"НЕАВТОРИЗОВАНИЙ ДОСТУП | UserID: {user_id} | Команда: {command}")
    
    def log_csrf_attack(self, user_id: int, callback_data: str) -> None:
        """Логування CSRF атак"""
        self.logger.warning(f"CSRF АТАКА | UserID: {user_id} | Callback: {callback_data[:50]}...")
    
    def log_info(self, message: str) -> None:
        """Логування інформаційних повідомлень"""
        self.logger.info(message)
    
    def log_error(self, error: str, user_id: Optional[int] = None) -> None:
        """Логування помилок"""
        if user_id:
            self.logger.error(f"UserID: {user_id} | Помилка: {error}")
        else:
            self.logger.error(f"Помилка: {error}")


# Глобальний екземпляр логера
logger = BotLogger()
