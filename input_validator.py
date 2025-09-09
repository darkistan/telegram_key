"""
Модуль для валідації вхідних даних
"""
import re
from typing import Dict, Any, Optional

from logger import logger


class InputValidator:
    """Клас для валідації вхідних даних"""
    
    def __init__(self):
        """Ініціалізація валідатора"""
        # Налаштування
        self.max_message_length = 1000  # Максимальна довжина повідомлення
        self.max_query_length = 200  # Максимальна довжина пошукового запиту
        self.max_group_name_length = 100  # Максимальна довжина назви групи
        
        # Паттерни для валідації
        self.uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
        self.pin_pattern = re.compile(r'^[0-9]{4,10}$')  # Пін-код: 4-10 цифр
        self.twofa_code_pattern = re.compile(r'^[0-9]{6}$')  # 2FA код: 6 цифр
    
    def validate_message_length(self, message: str) -> Dict[str, Any]:
        """
        Валідація довжини повідомлення
        
        Args:
            message: Повідомлення для перевірки
            
        Returns:
            Результат валідації
        """
        if not message:
            return {
                "valid": False,
                "message": "Повідомлення не може бути порожнім"
            }
        
        if len(message) > self.max_message_length:
            logger.log_error(f"Повідомлення занадто довге: {len(message)} символів")
            return {
                "valid": False,
                "message": f"Повідомлення занадто довге. Максимум {self.max_message_length} символів.",
                "current_length": len(message),
                "max_length": self.max_message_length
            }
        
        return {
            "valid": True,
            "message": "Повідомлення валідне"
        }
    
    def validate_search_query(self, query: str) -> Dict[str, Any]:
        """
        Валідація пошукового запиту
        
        Args:
            query: Пошуковий запит
            
        Returns:
            Результат валідації
        """
        if not query or not query.strip():
            return {
                "valid": False,
                "message": "Пошуковий запит не може бути порожнім"
            }
        
        query = query.strip()
        
        if len(query) > self.max_query_length:
            logger.log_error(f"Пошуковий запит занадто довгий: {len(query)} символів")
            return {
                "valid": False,
                "message": f"Пошуковий запит занадто довгий. Максимум {self.max_query_length} символів.",
                "current_length": len(query),
                "max_length": self.max_query_length
            }
        
        # Перевіряємо на підозрілі символи
        if self._contains_suspicious_chars(query):
            logger.log_error(f"Пошуковий запит містить підозрілі символи: {query}")
            return {
                "valid": False,
                "message": "Пошуковий запит містить недозволені символи"
            }
        
        return {
            "valid": True,
            "message": "Пошуковий запит валідний",
            "cleaned_query": query
        }
    
    def validate_group_name(self, group_name: str) -> Dict[str, Any]:
        """
        Валідація назви групи
        
        Args:
            group_name: Назва групи
            
        Returns:
            Результат валідації
        """
        if not group_name or not group_name.strip():
            return {
                "valid": False,
                "message": "Назва групи не може бути порожньою"
            }
        
        group_name = group_name.strip()
        
        if len(group_name) > self.max_group_name_length:
            logger.log_error(f"Назва групи занадто довга: {len(group_name)} символів")
            return {
                "valid": False,
                "message": f"Назва групи занадто довга. Максимум {self.max_group_name_length} символів.",
                "current_length": len(group_name),
                "max_length": self.max_group_name_length
            }
        
        return {
            "valid": True,
            "message": "Назва групи валідна",
            "cleaned_group_name": group_name
        }
    
    def validate_pin_code(self, pin: str) -> Dict[str, Any]:
        """
        Валідація пін-коду
        
        Args:
            pin: Пін-код
            
        Returns:
            Результат валідації
        """
        if not pin:
            return {
                "valid": False,
                "message": "Пін-код не може бути порожнім"
            }
        
        if not self.pin_pattern.match(pin):
            logger.log_error(f"Невірний формат пін-коду: {pin}")
            return {
                "valid": False,
                "message": "Пін-код повинен містити тільки цифри (4-10 символів)"
            }
        
        return {
            "valid": True,
            "message": "Пін-код валідний"
        }
    
    def validate_twofa_code(self, code: str) -> Dict[str, Any]:
        """
        Валідація 2FA коду
        
        Args:
            code: 2FA код
            
        Returns:
            Результат валідації
        """
        if not code:
            return {
                "valid": False,
                "message": "2FA код не може бути порожнім"
            }
        
        if not self.twofa_code_pattern.match(code):
            logger.log_error(f"Невірний формат 2FA коду: {code}")
            return {
                "valid": False,
                "message": "2FA код повинен містити рівно 6 цифр"
            }
        
        return {
            "valid": True,
            "message": "2FA код валідний"
        }
    
    def validate_uuid(self, uuid: str) -> Dict[str, Any]:
        """
        Валідація UUID
        
        Args:
            uuid: UUID для перевірки
            
        Returns:
            Результат валідації
        """
        if not uuid:
            return {
                "valid": False,
                "message": "UUID не може бути порожнім"
            }
        
        if not self.uuid_pattern.match(uuid):
            logger.log_error(f"Невірний формат UUID: {uuid}")
            return {
                "valid": False,
                "message": "Невірний формат UUID"
            }
        
        return {
            "valid": True,
            "message": "UUID валідний"
        }
    
    def _contains_suspicious_chars(self, text: str) -> bool:
        """
        Перевірка на підозрілі символи
        
        Args:
            text: Текст для перевірки
            
        Returns:
            True якщо знайдено підозрілі символи
        """
        # Список підозрілих символів
        suspicious_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']', '|', '\\', '/', '*', '?', '`', '~', '$']
        
        for char in suspicious_chars:
            if char in text:
                return True
        
        return False
    
    def sanitize_input(self, text: str) -> str:
        """
        Санітизація вхідного тексту
        
        Args:
            text: Текст для санітизації
            
        Returns:
            Санітизований текст
        """
        if not text:
            return ""
        
        # Видаляємо зайві пробіли
        text = text.strip()
        
        # Обмежуємо довжину
        if len(text) > self.max_message_length:
            text = text[:self.max_message_length]
        
        return text


# Глобальний екземпляр валідатора
input_validator = InputValidator()
