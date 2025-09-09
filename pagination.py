"""
Модуль постраничного виводу для Telegram-бота KeePass
"""
from typing import List, Dict, Any, Optional
from telegram import InlineKeyboardButton, InlineKeyboardMarkup

from csrf_manager import csrf_manager


class PaginationManager:
    """Клас для управління постраничним виводом"""
    
    def __init__(self, items_per_page: int = 10):
        """
        Ініціалізація менеджера пагінації
        
        Args:
            items_per_page: Кількість елементів на сторінці
        """
        self.items_per_page = items_per_page
    
    def create_search_results_keyboard(self, results: List[Dict[str, Any]], page: int = 0, user_id: int = None) -> InlineKeyboardMarkup:
        """
        Створення клавіатури з результатами пошуку
        
        Args:
            results: Список результатів пошуку
            page: Номер поточної сторінки
            user_id: ID користувача для CSRF токенів
            
        Returns:
            InlineKeyboardMarkup з результатами
        """
        if not results:
            return InlineKeyboardMarkup([])
        
        # Розраховуємо загальну кількість сторінок
        total_pages = (len(results) - 1) // self.items_per_page + 1
        
        # Обмежуємо номер сторінки
        page = max(0, min(page, total_pages - 1))
        
        # Отримуємо елементи для поточної сторінки
        start_idx = page * self.items_per_page
        end_idx = start_idx + self.items_per_page
        page_results = results[start_idx:end_idx]
        
        # Створюємо кнопки для результатів
        keyboard = []
        for i, result in enumerate(page_results):
            title = result.get("title", "Без назви")
            group = result.get("group", "")
            
            # Формуємо текст кнопки з групою
            if group:
                # Якщо є група, показуємо її
                if len(title) > 20:
                    title = title[:17] + "..."
                button_text = f"{start_idx + i + 1}. {title} ({group})"
            else:
                # Якщо групи немає, показуємо тільки назву
                if len(title) > 30:
                    title = title[:27] + "..."
                button_text = f"{start_idx + i + 1}. {title}"
            
            callback_data = f"e_{result['uuid']}"
            
            # Додаємо CSRF токен якщо є user_id
            if user_id:
                callback_data = csrf_manager.add_csrf_to_callback_data(user_id, callback_data)
            
            keyboard.append([InlineKeyboardButton(button_text, callback_data=callback_data)])
        
        # Додаємо кнопки навігації якщо потрібно
        if total_pages > 1:
            nav_buttons = []
            
            # Кнопка "Назад" (попередня сторінка)
            if page > 0:
                callback_data = f"p_{page-1}"
                if user_id:
                    callback_data = csrf_manager.add_csrf_to_callback_data(user_id, callback_data)
                nav_buttons.append(InlineKeyboardButton("⬅️ Назад", callback_data=callback_data))
            
            # Інформація про сторінку
            callback_data = "pi"
            if user_id:
                callback_data = csrf_manager.add_csrf_to_callback_data(user_id, callback_data)
            nav_buttons.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data=callback_data))
            
            # Кнопка "Вперед" (наступна сторінка)
            if page < total_pages - 1:
                callback_data = f"p_{page+1}"
                if user_id:
                    callback_data = csrf_manager.add_csrf_to_callback_data(user_id, callback_data)
                nav_buttons.append(InlineKeyboardButton("Вперёд ➡️", callback_data=callback_data))
            
            keyboard.append(nav_buttons)
        
        return InlineKeyboardMarkup(keyboard)
    
    def get_page_info(self, results: List[Dict[str, Any]], page: int = 0) -> str:
        """
        Отримання інформації про поточну сторінку
        
        Args:
            results: Список результатів пошуку
            page: Номер поточної сторінки
            
        Returns:
            Рядок з інформацією про сторінку
        """
        if not results:
            return "Результатів не знайдено"
        
        total_pages = (len(results) - 1) // self.items_per_page + 1
        page = max(0, min(page, total_pages - 1))
        
        start_idx = page * self.items_per_page
        end_idx = min(start_idx + self.items_per_page, len(results))
        
        return f"Сторінка {page + 1} з {total_pages} (елементи {start_idx + 1}-{end_idx} з {len(results)})"
    
    def create_admin_users_keyboard(self, users: List[Dict[str, Any]], page: int = 0) -> InlineKeyboardMarkup:
        """
        Створення клавіатури з користувачами для адміна
        
        Args:
            users: Список користувачів
            page: Номер поточної сторінки
            
        Returns:
            InlineKeyboardMarkup з користувачами
        """
        if not users:
            return InlineKeyboardMarkup([])
        
        # Розраховуємо загальну кількість сторінок
        total_pages = (len(users) - 1) // self.items_per_page + 1
        
        # Обмежуємо номер сторінки
        page = max(0, min(page, total_pages - 1))
        
        # Отримуємо елементи для поточної сторінки
        start_idx = page * self.items_per_page
        end_idx = start_idx + self.items_per_page
        page_users = users[start_idx:end_idx]
        
        # Створюємо кнопки для користувачів
        keyboard = []
        for i, user in enumerate(page_users):
            username = user.get("username", "без username")
            user_id = user.get("user_id", "невідомий")
            
            # Обмежуємо довжину username
            display_username = username
            if len(display_username) > 20:
                display_username = display_username[:17] + "..."
            
            button_text = f"{start_idx + i + 1}. @{display_username} ({user_id})"
            callback_data = f"revoke_{user_id}"
            
            keyboard.append([InlineKeyboardButton(button_text, callback_data=callback_data)])
        
        # Додаємо кнопки навігації якщо потрібно
        if total_pages > 1:
            nav_buttons = []
            
            # Кнопка "Назад"
            if page > 0:
                nav_buttons.append(InlineKeyboardButton("⬅️ Назад", callback_data=f"users_page_{page-1}"))
            
            # Інформація про сторінку
            nav_buttons.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data="users_page_info"))
            
            # Кнопка "Вперед"
            if page < total_pages - 1:
                nav_buttons.append(InlineKeyboardButton("Вперёд ➡️", callback_data=f"users_page_{page+1}"))
            
            keyboard.append(nav_buttons)
        
        return InlineKeyboardMarkup(keyboard)
    
    def create_back_keyboard(self, user_id: int = None) -> InlineKeyboardMarkup:
        """
        Створення клавіатури з кнопкою "Назад"
        
        Args:
            user_id: ID користувача для CSRF токенів
        
        Returns:
            InlineKeyboardMarkup з кнопкою "Назад"
        """
        callback_data = "bs"
        if user_id:
            callback_data = csrf_manager.add_csrf_to_callback_data(user_id, callback_data)
        
        keyboard = [[InlineKeyboardButton("🔙 Назад до пошуку", callback_data=callback_data)]]
        return InlineKeyboardMarkup(keyboard)


# Глобальний екземпляр менеджера пагінації
pagination_manager = PaginationManager()
