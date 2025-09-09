"""
Модуль для управління rate limiting
"""
import time
from datetime import datetime, timedelta
from typing import Dict, Optional
from collections import defaultdict

from logger import logger


class RateLimiter:
    """Клас для управління обмеженнями швидкості запитів"""
    
    def __init__(self, max_pin_attempts=5, max_twofa_attempts=3, max_requests_per_minute=10, 
                 pin_lockout_duration=300, twofa_lockout_duration=180):
        """Ініціалізація rate limiter"""
        # Зберігаємо спроби користувачів
        self.pin_attempts: Dict[int, list] = defaultdict(list)
        self.twofa_attempts: Dict[int, list] = defaultdict(list)
        self.request_counts: Dict[int, list] = defaultdict(list)
        
        # Налаштування
        self.max_pin_attempts = max_pin_attempts
        self.max_twofa_attempts = max_twofa_attempts
        self.max_requests_per_minute = max_requests_per_minute
        self.pin_lockout_duration = pin_lockout_duration
        self.twofa_lockout_duration = twofa_lockout_duration
        self.request_window = 60  # Вікно для підрахунку запитів (секунди)
    
    def check_pin_rate_limit(self, user_id: int) -> Dict[str, any]:
        """
        Перевірка rate limit для пін-коду
        
        Args:
            user_id: ID користувача
            
        Returns:
            Словник з результатом перевірки
        """
        current_time = time.time()
        user_attempts = self.pin_attempts[user_id]
        
        # Видаляємо старі спроби (старші ніж lockout_duration)
        user_attempts[:] = [attempt_time for attempt_time in user_attempts 
                           if current_time - attempt_time < self.pin_lockout_duration]
        
        # Перевіряємо чи не перевищено ліміт
        if len(user_attempts) >= self.max_pin_attempts:
            oldest_attempt = min(user_attempts)
            remaining_time = int(self.pin_lockout_duration - (current_time - oldest_attempt))
            
            logger.log_error(f"Rate limit для пін-коду перевищено для користувача {user_id}")
            return {
                "allowed": False,
                "message": f"Занадто багато спроб пін-коду. Спробуйте через {remaining_time} секунд.",
                "remaining_time": remaining_time
            }
        
        # Додаємо поточну спробу
        user_attempts.append(current_time)
        
        return {
            "allowed": True,
            "message": "Спроба пін-коду дозволена",
            "remaining_attempts": self.max_pin_attempts - len(user_attempts)
        }
    
    def check_twofa_rate_limit(self, user_id: int) -> Dict[str, any]:
        """
        Перевірка rate limit для 2FA коду
        
        Args:
            user_id: ID користувача
            
        Returns:
            Словник з результатом перевірки
        """
        current_time = time.time()
        user_attempts = self.twofa_attempts[user_id]
        
        # Видаляємо старі спроби
        user_attempts[:] = [attempt_time for attempt_time in user_attempts 
                           if current_time - attempt_time < self.twofa_lockout_duration]
        
        # Перевіряємо чи не перевищено ліміт
        if len(user_attempts) >= self.max_twofa_attempts:
            oldest_attempt = min(user_attempts)
            remaining_time = int(self.twofa_lockout_duration - (current_time - oldest_attempt))
            
            logger.log_error(f"Rate limit для 2FA перевищено для користувача {user_id}")
            return {
                "allowed": False,
                "message": f"Занадто багато спроб 2FA коду. Спробуйте через {remaining_time} секунд.",
                "remaining_time": remaining_time
            }
        
        # Додаємо поточну спробу
        user_attempts.append(current_time)
        
        return {
            "allowed": True,
            "message": "Спроба 2FA коду дозволена",
            "remaining_attempts": self.max_twofa_attempts - len(user_attempts)
        }
    
    def check_request_rate_limit(self, user_id: int) -> Dict[str, any]:
        """
        Перевірка rate limit для загальних запитів
        
        Args:
            user_id: ID користувача
            
        Returns:
            Словник з результатом перевірки
        """
        current_time = time.time()
        user_requests = self.request_counts[user_id]
        
        # Видаляємо старі запити (старші ніж request_window)
        user_requests[:] = [request_time for request_time in user_requests 
                           if current_time - request_time < self.request_window]
        
        # Перевіряємо чи не перевищено ліміт
        if len(user_requests) >= self.max_requests_per_minute:
            oldest_request = min(user_requests)
            remaining_time = int(self.request_window - (current_time - oldest_request))
            
            logger.log_error(f"Rate limit для запитів перевищено для користувача {user_id}")
            return {
                "allowed": False,
                "message": f"Занадто багато запитів. Спробуйте через {remaining_time} секунд.",
                "remaining_time": remaining_time
            }
        
        # Додаємо поточний запит
        user_requests.append(current_time)
        
        return {
            "allowed": True,
            "message": "Запит дозволений",
            "remaining_requests": self.max_requests_per_minute - len(user_requests)
        }
    
    def reset_pin_attempts(self, user_id: int) -> None:
        """Скидання спроб пін-коду для користувача"""
        if user_id in self.pin_attempts:
            del self.pin_attempts[user_id]
            logger.log_info(f"Скинуто спроби пін-коду для користувача {user_id}")
    
    def reset_twofa_attempts(self, user_id: int) -> None:
        """Скидання спроб 2FA для користувача"""
        if user_id in self.twofa_attempts:
            del self.twofa_attempts[user_id]
            logger.log_info(f"Скинуто спроби 2FA для користувача {user_id}")
    
    def get_pin_attempts_remaining(self, user_id: int) -> int:
        """Отримання кількості спроб пін-коду що залишились"""
        current_time = time.time()
        user_attempts = self.pin_attempts[user_id]
        
        # Видаляємо старі спроби
        user_attempts[:] = [attempt_time for attempt_time in user_attempts 
                           if current_time - attempt_time < self.pin_lockout_duration]
        
        return max(0, self.max_pin_attempts - len(user_attempts))
    
    def get_twofa_attempts_remaining(self, user_id: int) -> int:
        """Отримання кількості спроб 2FA що залишились"""
        current_time = time.time()
        user_attempts = self.twofa_attempts[user_id]
        
        # Видаляємо старі спроби
        user_attempts[:] = [attempt_time for attempt_time in user_attempts 
                           if current_time - attempt_time < self.twofa_lockout_duration]
        
        return max(0, self.max_twofa_attempts - len(user_attempts))


# Глобальний екземпляр rate limiter (ініціалізується в bot.py)
rate_limiter = None
