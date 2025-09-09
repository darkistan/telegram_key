"""
Модуль авторизації для Telegram-бота KeePass
"""
import json
import os
from datetime import datetime
from typing import List, Optional, Dict, Any
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ContextTypes

from logger import logger
from email_auth import email_2fa
from csrf_manager import csrf_manager


class AuthManager:
    """Клас для управління авторизацією користувачів"""
    
    def __init__(self, allowed_users_file: str = "allowed_users.json"):
        """
        Ініціалізація менеджера авторизації
        
        Args:
            allowed_users_file: Шлях до файлу з дозволеними користувачами
        """
        self.allowed_users_file = allowed_users_file
        self.allowed_users = self._load_allowed_users()
    
    def _load_allowed_users(self) -> Dict[str, Any]:
        """Завантаження списку дозволених користувачів"""
        if os.path.exists(self.allowed_users_file):
            try:
                with open(self.allowed_users_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.log_error(f"Помилка завантаження файлу користувачів: {e}")
                return {"users": [], "pending_requests": []}
        return {"users": [], "pending_requests": []}
    
    def _save_allowed_users(self) -> None:
        """Збереження списку дозволених користувачів"""
        try:
            with open(self.allowed_users_file, 'w', encoding='utf-8') as f:
                json.dump(self.allowed_users, f, ensure_ascii=False, indent=2)
        except IOError as e:
            logger.log_error(f"Помилка збереження файлу користувачів: {e}")
    
    def is_user_allowed(self, user_id: int) -> bool:
        """
        Перевірка чи дозволений користувач
        
        Args:
            user_id: ID користувача
            
        Returns:
            True якщо користувач дозволений
        """
        return str(user_id) in [str(u["user_id"]) for u in self.allowed_users["users"]]
    
    def add_user_request(self, user_id: int, username: str) -> None:
        """
        Додавання запиту на доступ (після успішного 2FA)
        
        Args:
            user_id: ID користувача
            username: Ім'я користувача
        """
        # Перевіряємо чи вже є запит
        for request in self.allowed_users["pending_requests"]:
            if request["user_id"] == user_id:
                return
        
        # Додаємо новий запит
        self.allowed_users["pending_requests"].append({
            "user_id": user_id,
            "username": username,
            "timestamp": str(datetime.now())
        })
        self._save_allowed_users()
        logger.log_access_request(user_id, username)
    
    def send_2fa_code(self, user_id: int, username: str, admin_email: str,
                     smtp_server: str, smtp_port: int, smtp_username: str, 
                     smtp_password: str) -> Optional[str]:
        """
        Відправка 2FA коду на email адміна
        
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
        return email_2fa.send_verification_code(
            user_id, username, admin_email,
            smtp_server, smtp_port, smtp_username, smtp_password
        )
    
    def verify_2fa_code(self, user_id: int, input_code: str) -> Dict[str, Any]:
        """
        Перевірка 2FA коду
        
        Args:
            user_id: ID користувача
            input_code: Введений код
            
        Returns:
            Результат перевірки
        """
        return email_2fa.verify_code(user_id, input_code)
    
    def resend_2fa_code(self, user_id: int, username: str, admin_email: str,
                       smtp_server: str, smtp_port: int, smtp_username: str, 
                       smtp_password: str) -> Optional[str]:
        """
        Повторна відправка 2FA коду
        
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
        return email_2fa.resend_code(
            user_id, username, admin_email,
            smtp_server, smtp_port, smtp_username, smtp_password
        )
    
    def approve_user(self, user_id: int, username: str) -> bool:
        """
        Схвалення користувача
        
        Args:
            user_id: ID користувача
            username: Ім'я користувача
            
        Returns:
            True якщо користувач був схвалений
        """
        # Видаляємо з pending_requests
        self.allowed_users["pending_requests"] = [
            req for req in self.allowed_users["pending_requests"] 
            if req["user_id"] != user_id
        ]
        
        # Додаємо до дозволених
        if not self.is_user_allowed(user_id):
            self.allowed_users["users"].append({
                "user_id": user_id,
                "username": username,
                "approved_at": str(datetime.now())
            })
            self._save_allowed_users()
            logger.log_access_granted(user_id, username)
            return True
        return False
    
    def deny_user(self, user_id: int, username: str) -> bool:
        """
        Відхилення користувача
        
        Args:
            user_id: ID користувача
            username: Ім'я користувача
            
        Returns:
            True якщо запит був відхилений
        """
        # Видаляємо з pending_requests
        original_count = len(self.allowed_users["pending_requests"])
        self.allowed_users["pending_requests"] = [
            req for req in self.allowed_users["pending_requests"] 
            if req["user_id"] != user_id
        ]
        
        if len(self.allowed_users["pending_requests"]) < original_count:
            self._save_allowed_users()
            logger.log_access_denied(user_id, username)
            return True
        return False
    
    def revoke_user_access(self, user_id: int) -> bool:
        """
        Відкликання доступу користувача
        
        Args:
            user_id: ID користувача
            
        Returns:
            True якщо доступ був відкликаний
        """
        original_count = len(self.allowed_users["users"])
        self.allowed_users["users"] = [
            user for user in self.allowed_users["users"] 
            if user["user_id"] != user_id
        ]
        
        if len(self.allowed_users["users"]) < original_count:
            self._save_allowed_users()
            return True
        return False
    
    def get_pending_requests(self) -> List[Dict[str, Any]]:
        """Отримання списку очікуючих запитів"""
        return self.allowed_users["pending_requests"].copy()
    
    def get_allowed_users(self) -> List[Dict[str, Any]]:
        """Отримання списку дозволених користувачів"""
        return self.allowed_users["users"].copy()
    
    def create_users_management_keyboard(self, users: List[Dict[str, Any]], page: int = 0, items_per_page: int = 10, admin_user_id: int = None) -> InlineKeyboardMarkup:
        """
        Створення клавіатури для управління користувачами
        
        Args:
            users: Список користувачів
            page: Номер сторінки
            items_per_page: Кількість елементів на сторінці
            admin_user_id: ID адміністратора для CSRF токенів
            
        Returns:
            InlineKeyboardMarkup з користувачами та кнопками видалення
        """
        if not users:
            return InlineKeyboardMarkup([])
        
        # Розраховуємо загальну кількість сторінок
        total_pages = (len(users) - 1) // items_per_page + 1
        
        # Обмежуємо номер сторінки
        page = max(0, min(page, total_pages - 1))
        
        # Отримуємо елементи для поточної сторінки
        start_idx = page * items_per_page
        end_idx = start_idx + items_per_page
        page_users = users[start_idx:end_idx]
        
        # Створюємо кнопки для користувачів
        keyboard = []
        for i, user in enumerate(page_users):
            username = user.get("username", "без username")
            user_id = user.get("user_id", "невідомий")
            
            # Обмежуємо довжину username
            display_username = username
            if len(display_username) > 15:
                display_username = display_username[:12] + "..."
            
            button_text = f"🗑️ {display_username} ({user_id})"
            callback_data = f"rm_{user_id}"
            
            # Додаємо CSRF токен якщо є admin_user_id
            if admin_user_id:
                callback_data = csrf_manager.add_csrf_to_callback_data(admin_user_id, callback_data)
            
            keyboard.append([InlineKeyboardButton(button_text, callback_data=callback_data)])
        
        # Додаємо кнопки навігації якщо потрібно
        if total_pages > 1:
            nav_buttons = []
            
            # Кнопка "Назад" (попередня сторінка)
            if page > 0:
                callback_data = f"up_{page-1}"
                if admin_user_id:
                    callback_data = csrf_manager.add_csrf_to_callback_data(admin_user_id, callback_data)
                nav_buttons.append(InlineKeyboardButton("⬅️ Назад", callback_data=callback_data))
            
            # Інформація про сторінку
            callback_data = "upi"
            if admin_user_id:
                callback_data = csrf_manager.add_csrf_to_callback_data(admin_user_id, callback_data)
            nav_buttons.append(InlineKeyboardButton(f"{page + 1}/{total_pages}", callback_data=callback_data))
            
            # Кнопка "Вперед" (наступна сторінка)
            if page < total_pages - 1:
                callback_data = f"up_{page+1}"
                if admin_user_id:
                    callback_data = csrf_manager.add_csrf_to_callback_data(admin_user_id, callback_data)
                nav_buttons.append(InlineKeyboardButton("Вперёд ➡️", callback_data=callback_data))
            
            keyboard.append(nav_buttons)
        
        # Додаємо кнопку "Назад до меню"
        callback_data = "back_to_menu"
        if admin_user_id:
            callback_data = csrf_manager.add_csrf_to_callback_data(admin_user_id, callback_data)
        keyboard.append([InlineKeyboardButton("🔙 Назад до меню", callback_data=callback_data)])
        
        return InlineKeyboardMarkup(keyboard)
    
    async def send_access_request_to_admin(self, update: Update, context: ContextTypes.DEFAULT_TYPE, admin_id: int) -> None:
        """
        Відправка запиту на доступ адміністратору
        
        Args:
            update: Об'єкт оновлення Telegram
            context: Контекст бота
            admin_id: ID адміністратора
        """
        user = update.effective_user
        username = user.username or "без username"
        
        # Додаємо запит
        self.add_user_request(user.id, username)
        
        # Створюємо inline клавіатуру з CSRF токенами
        approve_callback = csrf_manager.add_csrf_to_callback_data(admin_id, f"approve_{user.id}")
        deny_callback = csrf_manager.add_csrf_to_callback_data(admin_id, f"deny_{user.id}")
        
        keyboard = [
            [
                InlineKeyboardButton("✅ Разрешить", callback_data=approve_callback),
                InlineKeyboardButton("❌ Отклонить", callback_data=deny_callback)
            ]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        # Відправляємо повідомлення адміну
        message_text = (
            f"📢 Новый запрос на доступ\\n"
            f"👤 Пользователь: @{username}\\n"
            f"🆔 ID: {user.id}\\n\\n"
            f"Разрешить?"
        )
        
        try:
            await context.bot.send_message(
                chat_id=admin_id,
                text=message_text,
                reply_markup=reply_markup
            )
        except Exception as e:
            logger.log_error(f"Помилка відправки запиту адміну: {e}")
    
    async def handle_admin_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """
        Обробка callback від адміністратора
        
        Args:
            update: Об'єкт оновлення Telegram
            context: Контекст бота
        """
        query = update.callback_query
        await query.answer()
        
        data = query.data
        user_id = update.effective_user.id
        
        # CSRF захист для callback запитів
        if "|csrf:" in data:
            # Витягуємо оригінальні дані з перевіркою CSRF
            original_data = csrf_manager.extract_callback_data(user_id, data)
            if not original_data:
                await query.edit_message_text("❌ Невірний токен безпеки. Спробуйте ще раз.")
                return
            data = original_data
        else:
            # Для старих callback без CSRF токенів
            logger.log_error(f"Callback без CSRF токена для користувача {user_id}: {data}")
            await query.edit_message_text("❌ Помилка безпеки. Спробуйте ще раз.")
            return
        
        if data.startswith("approve_"):
            target_user_id = int(data.split("_")[1])
            # Знаходимо username з pending_requests
            username = "невідомий"
            for req in self.allowed_users["pending_requests"]:
                if req["user_id"] == target_user_id:
                    username = req["username"]
                    break
            
            if self.approve_user(target_user_id, username):
                # Логуємо адмін дію
                logger.log_admin_approve(user_id, target_user_id, username)
                await query.edit_message_text(f"✅ Доступ надано користувачу @{username}")
                # Повідомляємо користувача
                try:
                    await context.bot.send_message(
                        chat_id=target_user_id,
                        text="✅ Ваш запит на доступ схвалено! Тепер ви можете використовувати бота."
                    )
                except Exception as e:
                    logger.log_error(f"Помилка відправки повідомлення користувачу: {e}")
            else:
                await query.edit_message_text("❌ Помилка при наданні доступу")
        
        elif data.startswith("deny_"):
            target_user_id = int(data.split("_")[1])
            # Знаходимо username з pending_requests
            username = "невідомий"
            for req in self.allowed_users["pending_requests"]:
                if req["user_id"] == target_user_id:
                    username = req["username"]
                    break
            
            if self.deny_user(target_user_id, username):
                # Логуємо адмін дію
                logger.log_admin_deny(user_id, target_user_id, username)
                await query.edit_message_text(f"❌ Доступ відхилено для користувача @{username}")
                # Повідомляємо користувача
                try:
                    await context.bot.send_message(
                        chat_id=target_user_id,
                        text="❌ Доступ отклонён администратором."
                    )
                except Exception as e:
                    logger.log_error(f"Помилка відправки повідомлення користувачу: {e}")
            else:
                await query.edit_message_text("❌ Помилка при відхиленні доступу")


# Глобальний екземпляр менеджера авторизації
auth_manager = AuthManager()
