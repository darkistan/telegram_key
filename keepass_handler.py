"""
Модуль роботи з KeePass базою даних
"""
import os
import re
import time
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

from logger import logger


class KeePassHandler:
    """Клас для роботи з KeePass базою даних"""
    
    def __init__(self, db_path: str, password: str, key_file: Optional[str] = None):
        """
        Ініціалізація обробника KeePass
        
        Args:
            db_path: Шлях до файлу бази даних .kdbx
            password: Пароль для бази даних
            key_file: Шлях до ключового файлу (опціонально)
        """
        self.db_path = db_path
        self.password = password
        self.key_file = key_file
        self.kp = None
        self.last_modified = None
        self.last_reconnect = datetime.now()
        self.reconnect_interval = 300  # 5 хвилин
        self._connect()
    
    def _connect(self) -> None:
        """Підключення до бази даних KeePass"""
        try:
            if self.key_file and os.path.exists(self.key_file):
                self.kp = PyKeePass(self.db_path, password=self.password, keyfile=self.key_file)
            else:
                self.kp = PyKeePass(self.db_path, password=self.password)
            
            # Оновлюємо час останньої модифікації файлу
            self.last_modified = os.path.getmtime(self.db_path)
            self.last_reconnect = datetime.now()
            logger.logger.info(f"Успішно підключено до бази KeePass: {self.db_path}")
        except CredentialsError:
            logger.log_error("Невірний пароль або ключовий файл для бази KeePass")
            raise
        except Exception as e:
            logger.log_error(f"Неочікувана помилка підключення до KeePass: {e}")
            raise
    
    def _check_and_reconnect(self) -> bool:
        """
        Перевірка чи потрібно перепідключення до бази даних
        
        Returns:
            True якщо перепідключення відбулося
        """
        try:
            # Перевіряємо чи файл існує
            if not os.path.exists(self.db_path):
                logger.log_error(f"Файл бази даних не знайдено: {self.db_path}")
                return False
            
            # Перевіряємо час модифікації файлу
            current_modified = os.path.getmtime(self.db_path)
            
            # Перевіряємо чи пройшов мінімальний інтервал
            time_since_reconnect = datetime.now() - self.last_reconnect
            if time_since_reconnect.total_seconds() < self.reconnect_interval:
                return False
            
            # Перевіряємо чи файл змінився
            if self.last_modified is None or current_modified > self.last_modified:
                logger.log_info("Виявлено зміни в базі даних, виконуємо перепідключення...")
                self._reconnect()
                return True
            
            return False
            
        except Exception as e:
            logger.log_error(f"Помилка перевірки бази даних: {e}")
            return False
    
    def _reconnect(self) -> None:
        """Перепідключення до бази даних"""
        try:
            # Закриваємо поточне з'єднання
            if self.kp:
                del self.kp
                self.kp = None
            
            # Підключаємося знову
            self._connect()
            logger.log_info("Перепідключення до бази KeePass виконано успішно")
            
        except Exception as e:
            logger.log_error(f"Помилка перепідключення до KeePass: {e}")
            # Не піднімаємо виняток, щоб не зупинити роботу бота
    
    def force_reconnect(self) -> bool:
        """
        Примусове перепідключення до бази даних
        
        Returns:
            True якщо перепідключення успішне
        """
        try:
            self._reconnect()
            return True
        except Exception as e:
            logger.log_error(f"Помилка примусового перепідключення: {e}")
            return False
    
    def search_entries(self, query: str) -> List[Dict[str, Any]]:
        """
        Пошук записів у базі даних
        
        Args:
            query: Пошуковий запит
            
        Returns:
            Список знайдених записів
        """
        # Перевіряємо чи потрібно перепідключення
        self._check_and_reconnect()
        
        if not self.kp:
            logger.log_error("База даних KeePass не підключена")
            return []
        
        try:
            # Пошук нечутливий до регістру
            entries = []
            query_lower = query.lower()
            
            # Отримуємо всі записи та фільтруємо їх
            all_entries = self.kp.entries
            
            for entry in all_entries:
                # Перевіряємо всі поля на наявність запиту (нечутливо до регістру)
                title_match = entry.title and query_lower in entry.title.lower()
                username_match = entry.username and query_lower in entry.username.lower()
                url_match = entry.url and query_lower in entry.url.lower()
                notes_match = entry.notes and query_lower in entry.notes.lower()
                
                if title_match or username_match or url_match or notes_match:
                    entries.append(entry)
            
            logger.log_info(f"Пошук '{query}' (нечутливий до регістру): знайдено {len(entries)} записів")
            
            results = []
            for entry in entries:
                # Отримуємо додаткові поля
                expires = None
                if hasattr(entry, 'expires') and entry.expires and hasattr(entry.expires, 'strftime'):
                    expires = entry.expires.strftime("%d.%m.%Y %H:%M:%S")
                
                # Формуємо результат
                # Конвертуємо UUID в string безпечно
                uuid_str = str(entry.uuid) if hasattr(entry.uuid, '__str__') else entry.uuid.hex
                
                # Отримуємо повний шлях групи
                group_path = self._get_group_path(entry.group) if entry.group else ""
                
                result = {
                    "uuid": uuid_str,
                    "title": entry.title or "",
                    "username": entry.username or "",
                    "password": entry.password or "",
                    "url": entry.url or "",
                    "notes": entry.notes or "",
                    "group": group_path,
                    "expires": expires,
                    "icon": "🔑"  # Базовий іконка
                }
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.log_error(f"Помилка пошуку в KeePass: {e}")
            return []
    
    def search_entries_by_group(self, group_query: str) -> list:
        """Пошук записів за групою (нечутливий до регістру)"""
        # Перевіряємо чи потрібно перепідключення
        self._check_and_reconnect()
        
        try:
            logger.log_info(f"Пошук за групою '{group_query}' (нечутливий до регістру)")
            
            # Отримуємо всі записи
            entries = self.kp.entries
            results = []
            
            # Конвертуємо запит в нижній регістр для порівняння
            group_query_lower = group_query.lower()
            
            for entry in entries:
                # Отримуємо повний шлях групи
                group_path = self._get_group_path(entry.group) if entry.group else ""
                
                # Перевіряємо чи містить шлях групи запит (нечутливий до регістру)
                if group_query_lower in group_path.lower():
                    # Отримуємо додаткові поля
                    expires = None
                    if hasattr(entry, 'expires') and entry.expires and hasattr(entry.expires, 'strftime'):
                        expires = entry.expires.strftime("%d.%m.%Y %H:%M:%S")
                    
                    # Формуємо результат
                    # Конвертуємо UUID в string безпечно
                    uuid_str = str(entry.uuid) if hasattr(entry.uuid, '__str__') else entry.uuid.hex
                    
                    result = {
                        "uuid": uuid_str,
                        "title": entry.title or "",
                        "username": entry.username or "",
                        "password": entry.password or "",
                        "url": entry.url or "",
                        "notes": entry.notes or "",
                        "group": group_path,
                        "expires": expires,
                        "icon": "🔑"  # Базовий іконка
                    }
                    results.append(result)
            
            logger.log_info(f"Пошук за групою '{group_query}': знайдено {len(results)} записів")
            return results
            
        except Exception as e:
            logger.log_error(f"Помилка пошуку за групою в KeePass: {e}")
            return []
    
    def get_entry_by_uuid(self, uuid: str) -> Optional[Dict[str, Any]]:
        """
        Отримання запису за UUID
        
        Args:
            uuid: UUID запису
            
        Returns:
            Словник з даними запису або None
        """
        # Перевіряємо чи потрібно перепідключення
        self._check_and_reconnect()
        
        if not self.kp:
            logger.log_error("База даних KeePass не підключена")
            return None
        
        try:
            # Шукаємо запис за UUID серед всіх записів
            # Це більш надійний спосіб
            for entry in self.kp.entries:
                if str(entry.uuid) == uuid:
                    break
            else:
                return None
            
            # Отримуємо додаткові поля
            expires = None
            if hasattr(entry, 'expires') and entry.expires and hasattr(entry.expires, 'strftime'):
                expires = entry.expires.strftime("%d.%m.%Y %H:%M:%S")
            
            # Конвертуємо UUID в string безпечно
            uuid_str = str(entry.uuid) if hasattr(entry.uuid, '__str__') else entry.uuid.hex
            
            # Отримуємо повний шлях групи
            group_path = self._get_group_path(entry.group) if entry.group else ""
            
            return {
                "uuid": uuid_str,
                "title": entry.title or "",
                "username": entry.username or "",
                "password": entry.password or "",
                "url": entry.url or "",
                "notes": entry.notes or "",
                "group": group_path,
                "expires": expires,
                "icon": "🔑"  # Базовий іконка
            }
            
        except Exception as e:
            logger.log_error(f"Помилка отримання запису за UUID: {e}")
            return None
    
    def format_entry_for_display(self, entry: Dict[str, Any]) -> str:
        """
        Форматування запису для відображення (як у KeePass) - HTML формат
        
        Args:
            entry: Словник з даними запису
            
        Returns:
            Відформатований рядок для відображення в HTML
        """
        if not entry:
            return "❌ Запис не знайдено"
        
        # Функція для екранування HTML
        def escape_html(text):
            if not text:
                return ""
            return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        
        message_parts = []
        
        # Заголовок з іконкою
        title = escape_html(entry.get("title", "Без назви"))
        icon = entry.get("icon", "🔑")
        message_parts.append(f"{icon} <b>{title}</b>")
        message_parts.append("─" * 30)
        
        # Логін (Username)
        username = escape_html(entry.get("username", ""))
        if username:
            message_parts.append(f"👤 <b>Логін:</b> <code>{username}</code>")
        else:
            message_parts.append("👤 <b>Логін:</b> <i>(не встановлено)</i>")
        
        # Пароль (Password)
        password = escape_html(entry.get("password", ""))
        if password:
            # Показуємо силу пароля
            strength = self._calculate_password_strength(password)
            message_parts.append(f"🔒 <b>Пароль:</b> <code>{password}</code>")
            message_parts.append(f"💪 <b>Якість:</b> {strength}")
        else:
            message_parts.append("🔒 <b>Пароль:</b> <i>(не встановлено)</i>")
        
        # URL-посилання
        url = escape_html(entry.get("url", ""))
        if url:
            message_parts.append(f"🌐 <b>URL-посилання:</b> {url}")
        else:
            message_parts.append("🌐 <b>URL-посилання:</b> <i>(не встановлено)</i>")
        
        # Нотатки
        notes = entry.get("notes", "")
        if notes:
            # Обмежуємо довжину нотаток
            if len(notes) > 300:
                notes = notes[:297] + "..."
            notes_escaped = escape_html(notes)
            message_parts.append(f"📝 <b>Нотатки:</b>")
            message_parts.append(f"<i>{notes_escaped}</i>")
        else:
            message_parts.append("📝 <b>Нотатки:</b> <i>(не встановлено)</i>")
        
        # Термін дії
        expires = entry.get("expires")
        if expires:
            message_parts.append(f"⏰ <b>Термін дії:</b> {escape_html(expires)}")
        else:
            message_parts.append("⏰ <b>Термін дії:</b> <i>(не встановлено)</i>")
        
        # Група
        group = escape_html(entry.get("group", ""))
        if group:
            message_parts.append(f"📁 <b>Група:</b> {group}")
        
        return "\n".join(message_parts)
    
    def _get_group_path(self, group) -> str:
        """
        Отримання повного шляху групи
        
        Args:
            group: Об'єкт групи KeePass
            
        Returns:
            Повний шлях групи через слеш
        """
        if not group:
            return ""
        
        try:
            # У pykeepass групи мають атрибут path, який містить повний шлях як список
            if hasattr(group, 'path') and group.path:
                # path - це список, об'єднуємо його через слеш
                if isinstance(group.path, list):
                    path = "/".join(group.path)
                else:
                    path = str(group.path)
                
                # Прибираємо "Root/" з початку, якщо є
                if path.startswith("Root/"):
                    path = path[5:]  # Прибираємо "Root/"
                return path
            else:
                # Якщо path недоступний, використовуємо name
                return group.name if group.name and group.name != "Root" else ""
        except Exception as e:
            logger.log_error(f"Помилка отримання шляху групи: {e}")
            # Fallback до простого name
            return group.name if group.name and group.name != "Root" else ""
    
    def _calculate_password_strength(self, password: str) -> str:
        """
        Розрахунок якості пароля
        
        Args:
            password: Пароль для аналізу
            
        Returns:
            Рядок з описом якості пароля
        """
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        score = 0
        if length >= 8:
            score += 1
        if length >= 12:
            score += 1
        if has_upper:
            score += 1
        if has_lower:
            score += 1
        if has_digit:
            score += 1
        if has_special:
            score += 1
        
        if score <= 2:
            return f"Слабкий ({length} символів)"
        elif score <= 4:
            return f"Середній ({length} символів)"
        else:
            return f"Сильний ({length} символів)"
    
    def get_all_entries(self) -> List[Dict[str, Any]]:
        """
        Отримання всіх записів з бази даних
        
        Returns:
            Список всіх записів
        """
        # Перевіряємо чи потрібно перепідключення
        self._check_and_reconnect()
        
        if not self.kp:
            logger.log_error("База даних KeePass не підключена")
            return []
        
        try:
            entries = self.kp.entries
            results = []
            
            for entry in entries:
                # Отримуємо повний шлях групи
                group_path = self._get_group_path(entry.group) if entry.group else ""
                
                result = {
                    "uuid": str(entry.uuid),
                    "title": entry.title or "",
                    "username": entry.username or "",
                    "password": entry.password or "",
                    "url": entry.url or "",
                    "notes": entry.notes or "",
                    "group": group_path
                }
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.log_error(f"Помилка отримання всіх записів: {e}")
            return []
    
    def is_connected(self) -> bool:
        """
        Перевірка чи підключена база даних
        
        Returns:
            True якщо база підключена
        """
        return self.kp is not None


# Глобальний екземпляр обробника KeePass
keepass_handler = None


def init_keepass_handler(db_path: str, password: str, key_file: Optional[str] = None) -> KeePassHandler:
    """
    Ініціалізація глобального обробника KeePass
    
    Args:
        db_path: Шлях до файлу бази даних
        password: Пароль для бази даних
        key_file: Шлях до ключового файлу
        
    Returns:
        Екземпляр обробника KeePass
    """
    global keepass_handler
    keepass_handler = KeePassHandler(db_path, password, key_file)
    return keepass_handler


def get_keepass_handler() -> Optional[KeePassHandler]:
    """
    Отримання глобального обробника KeePass
    
    Returns:
        Екземпляр обробника KeePass або None
    """
    return keepass_handler
