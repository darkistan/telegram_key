#!/usr/bin/env python3
"""
Виправлена версія бота з детальним логуванням
"""
import os
import logging
from typing import Optional
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, ContextTypes, MessageHandler, filters

from auth import auth_manager
from keepass_handler import init_keepass_handler, get_keepass_handler
from pagination import pagination_manager
from logger import logger
from rate_limiter import RateLimiter
from csrf_manager import csrf_manager
from input_validator import input_validator

# Завантажуємо змінні середовища
load_dotenv("config.env")

# Конфігурація
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
ADMIN_USER_ID = int(os.getenv("ADMIN_USER_ID", "0"))
ACCESS_PIN = os.getenv("ACCESS_PIN", "1234")
KEEPASS_DB_PATH = os.getenv("KEEPASS_DB_PATH", "database.kdbx")
KEEPASS_PASSWORD = os.getenv("KEEPASS_PASSWORD")
KEEPASS_KEY_FILE = os.getenv("KEEPASS_KEY_FILE")

# Email 2FA конфігурація
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

# KeePass перепідключення конфігурація
KEEPASS_RECONNECT_INTERVAL = int(os.getenv("KEEPASS_RECONNECT_INTERVAL", "300"))  # 5 хвилин за замовчуванням

# Rate Limiting конфігурація
MAX_PIN_ATTEMPTS = int(os.getenv("MAX_PIN_ATTEMPTS", "5"))
MAX_2FA_ATTEMPTS = int(os.getenv("MAX_2FA_ATTEMPTS", "3"))
MAX_REQUESTS_PER_MINUTE = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "10"))
PIN_LOCKOUT_DURATION = int(os.getenv("PIN_LOCKOUT_DURATION", "300"))
TWOFA_LOCKOUT_DURATION = int(os.getenv("2FA_LOCKOUT_DURATION", "180"))

# Глобальні змінні для зберігання результатів пошуку
search_results = {}
current_page = {}

# Глобальний екземпляр rate limiter (ініціалізується в main())
rate_limiter = None


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обробка команди /start"""
    user = update.effective_user
    user_id = user.id
    
    if auth_manager.is_user_allowed(user_id):
        # Показуємо меню для авторизованого користувача
        keyboard = create_menu_keyboard(user_id)
        
        if user_id == ADMIN_USER_ID:
            message_text = "👑 Ви адміністратор"
        else:
            message_text = "✅ Ви маєте доступ до бота"
        
        await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
    else:
        # Показуємо меню для неавторизованого користувача
        keyboard = create_menu_keyboard(user_id)
        message_text = "🔐 Для доступу потрібна авторизація"
        
        await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')


async def search_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обробка команди /search"""
    user_id = update.effective_user.id
    
    if not auth_manager.is_user_allowed(user_id):
        logger.log_unauthorized_access_attempt(user_id, "/search")
        await update.message.reply_text("❌ У вас немає доступу до бота.")
        return
    
    keepass = get_keepass_handler()
    
    if not keepass or not keepass.is_connected():
        await update.message.reply_text("❌ База даних KeePass недоступна.")
        return
    
    # Запитуємо введення пошукового запиту
    await update.message.reply_text(
        "🔍 **Пошук у базі KeePass**\n\n"
        "Введіть запит для пошуку:\n"
        "• Назва запису\n"
        "• Логін\n"
        "• URL\n"
        "• Будь-який текст з запису\n\n"
        "Пошук нечутливий до регістру."
    )
    
    # Встановлюємо стан очікування введення для цього користувача
    context.user_data['waiting_for_search'] = True


async def list_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обробка команди /list"""
    user_id = update.effective_user.id
    
    if not auth_manager.is_user_allowed(user_id):
        logger.log_unauthorized_access_attempt(user_id, "/list")
        await update.message.reply_text("❌ У вас немає доступу до бота.")
        return
    
    keepass = get_keepass_handler()
    
    if not keepass or not keepass.is_connected():
        await update.message.reply_text("❌ База даних KeePass недоступна.")
        return
    
    try:
        # Отримуємо всі записи
        all_entries = keepass.get_all_entries()
        
        if not all_entries:
            await update.message.reply_text("❌ База даних порожня.")
            return
        
        # Зберігаємо результати для цього користувача
        search_results[user_id] = all_entries
        current_page[user_id] = 0
        
        if len(all_entries) <= 10:
            # Якщо записів мало, показуємо всі
            keyboard = pagination_manager.create_search_results_keyboard(all_entries, 0, user_id)
            message_text = f"📋 **Всі записи в базі**\n\nЗнайдено: {len(all_entries)} записів"
            await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
        else:
            # Якщо багато записів, показуємо з пагінацією
            keyboard = pagination_manager.create_search_results_keyboard(all_entries, 0, user_id)
            page_info = pagination_manager.get_page_info(all_entries, 0)
            message_text = f"📋 **Всі записи в базі**\n\n{page_info}"
            await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
    
    except Exception as e:
        logger.log_error(f"Помилка отримання списку записів: {e}", user_id)
        await update.message.reply_text("❌ Помилка при отриманні списку записів.")


async def admin_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обробка команди /admin"""
    user_id = update.effective_user.id
    
    # Перевіряємо, чи це адміністратор
    if user_id != ADMIN_USER_ID:
        logger.log_unauthorized_access_attempt(user_id, "/admin")
        await update.message.reply_text("❌ У вас немає прав адміністратора.")
        return
    
    # Логуємо доступ до адмін панелі
    logger.log_admin_panel_access(user_id)
    
    # Отримуємо список користувачів
    users = auth_manager.get_allowed_users()
    
    if not users:
        await update.message.reply_text("📋 **Панель адміністратора**\n\nНемає користувачів для управління.")
        return
    
    # Створюємо клавіатуру для управління користувачами
    keyboard = auth_manager.create_users_management_keyboard(users, 0, 10, ADMIN_USER_ID)
    
    message_text = f"📋 **Панель адміністратора**\n\nКористувачі з доступом: {len(users)}\n\nНатисніть на користувача для видалення:"
    
    await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')


async def handle_text_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обробка текстових повідомлень (пін-код, email код та пошукові запити)"""
    user_id = update.effective_user.id
    message_text = update.message.text.strip()
    user = update.effective_user
    username = user.username or "без username"
    
    # Валідація довжини повідомлення
    message_validation = input_validator.validate_message_length(message_text)
    if not message_validation["valid"]:
        await update.message.reply_text(f"❌ {message_validation['message']}")
        return
    
    # Rate limiting для загальних запитів
    request_limit = rate_limiter.check_request_rate_limit(user_id)
    if not request_limit["allowed"]:
        attempts = MAX_REQUESTS_PER_MINUTE - request_limit.get("remaining_requests", 0)
        logger.log_rate_limit_exceeded(user_id, "загальні запити", attempts, MAX_REQUESTS_PER_MINUTE)
        await update.message.reply_text(f"⏰ {request_limit['message']}")
        return
    
    # Перевіряємо, чи очікуємо пін-код від цього користувача
    if context.user_data.get('waiting_for_pin', False):
        # Валідація пін-коду
        pin_validation = input_validator.validate_pin_code(message_text)
        if not pin_validation["valid"]:
            await update.message.reply_text(f"❌ {pin_validation['message']}")
            return
        
        # Rate limiting для пін-коду
        pin_limit = rate_limiter.check_pin_rate_limit(user_id)
        if not pin_limit["allowed"]:
            attempts = MAX_PIN_ATTEMPTS - pin_limit.get("remaining_attempts", 0)
            logger.log_rate_limit_exceeded(user_id, "пін-код", attempts, MAX_PIN_ATTEMPTS)
            await update.message.reply_text(f"⏰ {pin_limit['message']}")
            return
        
        if message_text == ACCESS_PIN:
            # Пін-код правильний, скидаємо rate limiting та відправляємо 2FA код
            rate_limiter.reset_pin_attempts(user_id)
            context.user_data['waiting_for_pin'] = False
            context.user_data['waiting_for_email_code'] = True
            
            # Перевіряємо наявність email конфігурації
            if not all([ADMIN_EMAIL, SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD]):
                await update.message.reply_text(
                    "❌ Помилка конфігурації email. Зверніться до адміністратора."
                )
                return
            
            # Відправляємо 2FA код
            code = auth_manager.send_2fa_code(
                user_id, username, ADMIN_EMAIL,
                SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD
            )
            
            if code:
                await update.message.reply_text(
                    f"✅ Пін-код правильний!\n\n"
                    f"📧 Код відправлено на email адміна, отримайте його та введіть.\n\n"
                    f"Код дійсний протягом 60 хвилин."
                )
            else:
                await update.message.reply_text(
                    "❌ Помилка відправки коду. Спробуйте ще раз або зверніться до адміністратора."
                )
                context.user_data['waiting_for_pin'] = True
                context.user_data['waiting_for_email_code'] = False
        else:
            attempts = MAX_PIN_ATTEMPTS - pin_limit.get("remaining_attempts", 0)
            logger.log_invalid_pin(user_id, attempts, MAX_PIN_ATTEMPTS)
            await update.message.reply_text("❌ Невірний пін-код. Спробуйте ще раз або зверніться до адміністратора.")
        return
    
    # Перевіряємо, чи очікуємо email код від цього користувача
    if context.user_data.get('waiting_for_email_code', False):
        # Перевіряємо чи це команда повторної відправки
        if message_text.lower() == 'resend':
            # Повторна відправка коду
            code = auth_manager.resend_2fa_code(
                user_id, username, ADMIN_EMAIL,
                SMTP_SERVER, SMTP_PORT, SMTP_USERNAME, SMTP_PASSWORD
            )
            
            if code:
                await update.message.reply_text(
                    f"📧 Код повторно відправлено на email адміна.\n\n"
                    f"Код дійсний протягом 60 хвилин."
                )
            else:
                await update.message.reply_text(
                    "❌ Помилка повторної відправки коду. Спробуйте ще раз або зверніться до адміністратора."
                )
            return
        
        # Валідація 2FA коду
        twofa_validation = input_validator.validate_twofa_code(message_text)
        if not twofa_validation["valid"]:
            await update.message.reply_text(f"❌ {twofa_validation['message']}")
            return
        
        # Rate limiting для 2FA коду
        twofa_limit = rate_limiter.check_twofa_rate_limit(user_id)
        if not twofa_limit["allowed"]:
            attempts = MAX_2FA_ATTEMPTS - twofa_limit.get("remaining_attempts", 0)
            logger.log_rate_limit_exceeded(user_id, "2FA код", attempts, MAX_2FA_ATTEMPTS)
            await update.message.reply_text(f"⏰ {twofa_limit['message']}")
            return
        
        # Перевіряємо 2FA код
        result = auth_manager.verify_2fa_code(user_id, message_text)
        
        if result["success"]:
            # Код правильний, відправляємо запит адміну
            context.user_data['waiting_for_email_code'] = False
            await update.message.reply_text("✅ Код підтверджено! Запит на доступ відправлено адміністратору.")
            await auth_manager.send_access_request_to_admin(update, context, ADMIN_USER_ID)
        else:
            attempts = MAX_2FA_ATTEMPTS - twofa_limit.get("remaining_attempts", 0)
            logger.log_invalid_2fa(user_id, attempts, MAX_2FA_ATTEMPTS)
            if result["can_retry"]:
                await update.message.reply_text(
                    f"❌ {result['message']}\n\n"
                    f"Спробуйте ще раз або надішліть 'resend' для повторної відправки коду."
                )
            else:
                await update.message.reply_text(
                    f"❌ {result['message']}\n\n"
                    f"Для повторного запиту надішліть /start"
                )
                context.user_data['waiting_for_email_code'] = False
        return
    
    if not auth_manager.is_user_allowed(user_id):
        logger.log_unauthorized_access_attempt(user_id, "текстове повідомлення")
        await update.message.reply_text("❌ У вас немає доступу до бота.")
        return
    
    # Перевіряємо, чи очікуємо пошуковий запит від цього користувача
    if context.user_data.get('waiting_for_search', False):
        # Валідація пошукового запиту
        query_validation = input_validator.validate_search_query(message_text)
        if not query_validation["valid"]:
            await update.message.reply_text(f"❌ {query_validation['message']}")
            return
        
        # Обробка пошукового запиту
        await process_search_query(update, context, query_validation["cleaned_query"])
        return
    
    # Перевіряємо, чи очікуємо запит групи від цього користувача
    if context.user_data.get('waiting_for_group', False):
        # Валідація назви групи
        group_validation = input_validator.validate_group_name(message_text)
        if not group_validation["valid"]:
            await update.message.reply_text(f"❌ {group_validation['message']}")
            return
        
        # Обробка пошуку за групою
        await process_group_query(update, context, group_validation["cleaned_group_name"])
        return
    
    # Якщо не очікуємо жодного вводу
    await update.message.reply_text(
        "❓ Не розумію вашого повідомлення.\n\n"
        "Доступні команди:\n"
        "/search - пошук у базі KeePass\n"
        "/group - пошук за групою\n"
        "/list - показати всі записи\n"
        "/help - довідка"
    )


async def process_search_query(update: Update, context: ContextTypes.DEFAULT_TYPE, query: str) -> None:
    """Обробка пошукового запиту"""
    user_id = update.effective_user.id
    
    if not query:
        await update.message.reply_text("❌ Введіть запит для пошуку.")
        return
    
    keepass = get_keepass_handler()
    
    if not keepass or not keepass.is_connected():
        await update.message.reply_text("❌ База даних KeePass недоступна.")
        return
    
    try:
        results = keepass.search_entries(query)
        logger.log_search(user_id, query, len(results))
        
        # Скидаємо стан очікування
        context.user_data['waiting_for_search'] = False
        
        if not results:
            await update.message.reply_text("❌ Нічого не знайдено.")
            return
        
        # Зберігаємо результати для цього користувача
        search_results[user_id] = results
        current_page[user_id] = 0
        
        if len(results) <= 10:
            # Якщо результатів мало, показуємо всі
            keyboard = pagination_manager.create_search_results_keyboard(results, 0, user_id)
            message_text = f"🔍 **Результати пошуку для \"{query}\"**\n\nЗнайдено: {len(results)} записів"
            await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
        else:
            # Якщо багато результатів, показуємо з пагінацією
            keyboard = pagination_manager.create_search_results_keyboard(results, 0, user_id)
            page_info = pagination_manager.get_page_info(results, 0)
            message_text = f"🔍 **Результати пошуку для \"{query}\"**\n\n{page_info}"
            await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
    
    except Exception as e:
        logger.log_error(f"Помилка пошуку: {e}", user_id)
        await update.message.reply_text("❌ Помилка при пошуку в базі даних.")


async def process_group_query(update: Update, context: ContextTypes.DEFAULT_TYPE, group_query: str) -> None:
    """Обробка пошуку за групою"""
    user_id = update.effective_user.id
    
    if not group_query:
        await update.message.reply_text("❌ Введіть назву групи для пошуку.")
        return
    
    keepass = get_keepass_handler()
    
    if not keepass or not keepass.is_connected():
        await update.message.reply_text("❌ База даних KeePass недоступна.")
        return
    
    try:
        results = keepass.search_entries_by_group(group_query)
        logger.log_search(user_id, f"група: {group_query}", len(results))
        
        # Скидаємо стан очікування
        context.user_data['waiting_for_group'] = False
        
        if not results:
            await update.message.reply_text(f"❌ В групі '{group_query}' не знайдено записів.")
            return
        
        # Зберігаємо результати для цього користувача
        search_results[user_id] = results
        current_page[user_id] = 0
        
        if len(results) <= 10:
            # Якщо результатів мало, показуємо всі
            keyboard = pagination_manager.create_search_results_keyboard(results, 0, user_id)
            message_text = f"📁 **Записи в групі '{group_query}'**\n\nЗнайдено: {len(results)} записів"
            await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
        else:
            # Якщо багато результатів, показуємо з пагінацією
            keyboard = pagination_manager.create_search_results_keyboard(results, 0, user_id)
            page_info = pagination_manager.get_page_info(results, 0)
            message_text = f"📁 **Записи в групі '{group_query}'**\n\n{page_info}"
            await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
    
    except Exception as e:
        logger.log_error(f"Помилка пошуку за групою: {e}", user_id)
        await update.message.reply_text("❌ Помилка при пошуку в базі даних.")


async def group_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда пошуку за групою"""
    user_id = update.effective_user.id
    
    if not auth_manager.is_user_allowed(user_id):
        logger.log_unauthorized_access_attempt(user_id, "/group")
        await update.message.reply_text(
            f"🔐 **Доступ заборонено**\n\n"
            f"Для отримання доступу введіть пін-код: `{ACCESS_PIN}`\n\n"
            f"Після введення пін-коду адміністратор розгляне ваш запит.",
            parse_mode='Markdown'
        )
        context.user_data['waiting_for_pin'] = True
        return
    
    # Встановлюємо стан очікування введення групи
    context.user_data['waiting_for_group'] = True
    context.user_data['waiting_for_search'] = False
    context.user_data['waiting_for_pin'] = False
    
    await update.message.reply_text(
        "🔍 **Пошук за групою**\n\n"
        "Введіть назву групи для пошуку записів.\n"
        "Наприклад: `Email`, `AD HTZ`, `DZTM`",
        parse_mode='Markdown'
    )


async def reconnect_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда перепідключення до бази даних"""
    user_id = update.effective_user.id
    
    if not auth_manager.is_user_allowed(user_id):
        logger.log_unauthorized_access_attempt(user_id, "/reconnect")
        await update.message.reply_text("❌ У вас немає доступу до бота.")
        return
    
    # Перевіряємо чи це адміністратор
    if user_id != ADMIN_USER_ID:
        await update.message.reply_text("❌ Тільки адміністратор може використовувати цю команду.")
        return
    
    keepass = get_keepass_handler()
    if not keepass:
        await update.message.reply_text("❌ KeePass обробник не ініціалізований.")
        return
    
    try:
        if keepass.force_reconnect():
            await update.message.reply_text("✅ Перепідключення до бази даних виконано успішно!")
            logger.log_info(f"Адміністратор {user_id} виконав перепідключення до бази даних")
        else:
            await update.message.reply_text("❌ Помилка при перепідключенні до бази даних.")
    except Exception as e:
        logger.log_error(f"Помилка команди перепідключення: {e}", user_id)
        await update.message.reply_text("❌ Помилка при перепідключенні до бази даних.")


async def menu_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда меню з кнопками"""
    user_id = update.effective_user.id
    
    # Створюємо клавіатуру залежно від ролі користувача
    keyboard = create_menu_keyboard(user_id)
    
    if auth_manager.is_user_allowed(user_id):
        # Авторизований користувач
        if user_id == ADMIN_USER_ID:
            # Адміністратор
            message_text = "👑 Ви адміністратор"
        else:
            # Звичайний користувач
            message_text = "✅ Ви маєте доступ до бота"
    else:
        # Неавторизований користувач
        message_text = "🔐 Для доступу потрібна авторизація"
    
    await update.message.reply_text(message_text, reply_markup=keyboard, parse_mode='Markdown')


def create_menu_keyboard(user_id: int) -> InlineKeyboardMarkup:
    """Створення клавіатури меню залежно від ролі користувача"""
    keyboard = []
    
    if auth_manager.is_user_allowed(user_id):
        # Авторизований користувач
        if user_id == ADMIN_USER_ID:
            # Адміністратор - всі команди
            keyboard.extend([
                [InlineKeyboardButton("🔍 Пошук", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_search"))],
                [InlineKeyboardButton("📁 Група", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_group"))],
                [InlineKeyboardButton("📋 Список", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_list"))],
                [InlineKeyboardButton("⚙️ Адмін панель", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_admin"))],
                [InlineKeyboardButton("🔄 Перепідключення", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_reconnect"))],
                [InlineKeyboardButton("ℹ️ Допомога", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_help"))]
            ])
        else:
            # Звичайний користувач - основні команди
            keyboard.extend([
                [InlineKeyboardButton("🔍 Пошук", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_search"))],
                [InlineKeyboardButton("📁 Група", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_group"))],
                [InlineKeyboardButton("📋 Список", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_list"))],
                [InlineKeyboardButton("ℹ️ Допомога", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_help"))]
            ])
    else:
        # Неавторизований користувач - тільки запит доступу
        keyboard.append([InlineKeyboardButton("🔐 Запросити доступ", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_request_access"))])
    
    return InlineKeyboardMarkup(keyboard)


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Команда довідки"""
    user_id = update.effective_user.id
    
    if not auth_manager.is_user_allowed(user_id):
        logger.log_unauthorized_access_attempt(user_id, "/help")
        await update.message.reply_text("❌ У вас немає доступу до бота.")
        return
    
    help_text = """
🤖 **KeePass Telegram Bot - Довідка**

**Основні команди:**
• `/start` - перевірка доступу та початок роботи
• `/search` - пошук записів у базі KeePass
• `/group` - пошук записів за групою
• `/list` - показати всі записи з бази
• `/help` - ця довідка

**Для адміністратора:**
• `/admin` - панель управління користувачами
• `/reconnect` - перепідключення до бази даних

**Як користуватися:**

🔍 **Пошук записів:**
1. Надішліть `/search`
2. Введіть запит для пошуку
3. Оберіть запис з результату

📁 **Пошук за групою:**
1. Надішліть `/group`
2. Введіть назву групи (наприклад: `Email`)
3. Переглядайте записи в цій групі

📋 **Список всіх записів:**
1. Надішліть `/list`
2. Переглядайте всі записи з пагінацією

**Примітки:**
• Пошук нечутливий до регістру
• Всі дії логуються для безпеки
• Для доступу потрібен пін-код (запитуйте у адміністратора)
    """
    
    await update.message.reply_text(help_text, parse_mode='Markdown')


async def handle_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE, data: str) -> None:
    """Обробка callback команд меню"""
    query = update.callback_query
    user_id = update.effective_user.id
    
    # Витягуємо команду з callback даних
    command = data.split("_", 1)[1] if "_" in data else data
    
    if command == "search":
        if not auth_manager.is_user_allowed(user_id):
            logger.log_unauthorized_access_attempt(user_id, "menu callback search")
            await query.edit_message_text("❌ У вас немає доступу до бота.")
            return
        
        # Виконуємо логіку пошуку без виклику команди
        keepass = get_keepass_handler()
        
        if not keepass or not keepass.is_connected():
            await query.edit_message_text("❌ База даних KeePass недоступна.")
            return
        
        # Створюємо кнопку повернення в меню
        back_keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
        ]])
        
        await query.edit_message_text(
            "🔍 **Пошук у базі KeePass**\n\n"
            "Введіть запит для пошуку:\n"
            "• Назва запису\n"
            "• Логін\n"
            "• URL\n"
            "• Будь-який текст з запису\n\n"
            "Пошук нечутливий до регістру.",
            reply_markup=back_keyboard
        )
        
        # Встановлюємо стан очікування введення для цього користувача
        context.user_data['waiting_for_search'] = True
        
    elif command == "group":
        if not auth_manager.is_user_allowed(user_id):
            logger.log_unauthorized_access_attempt(user_id, "menu callback group")
            await query.edit_message_text("❌ У вас немає доступу до бота.")
            return
        
        # Встановлюємо стан очікування введення групи
        context.user_data['waiting_for_group'] = True
        context.user_data['waiting_for_search'] = False
        context.user_data['waiting_for_pin'] = False
        
        # Створюємо кнопку повернення в меню
        back_keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
        ]])
        
        await query.edit_message_text(
            "🔍 **Пошук за групою**\n\n"
            "Введіть назву групи для пошуку записів.\n"
            "Наприклад: `Email`, `AD HTZ`, `DZTM`",
            parse_mode='Markdown',
            reply_markup=back_keyboard
        )
        
    elif command == "list":
        if not auth_manager.is_user_allowed(user_id):
            logger.log_unauthorized_access_attempt(user_id, "menu callback list")
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("❌ У вас немає доступу до бота.", reply_markup=back_keyboard)
            return
        
        # Виконуємо логіку списку без виклику команди
        keepass = get_keepass_handler()
        
        if not keepass or not keepass.is_connected():
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("❌ База даних KeePass недоступна.", reply_markup=back_keyboard)
            return
        
        try:
            # Отримуємо всі записи
            all_entries = keepass.get_all_entries()
            
            if not all_entries:
                # Створюємо кнопку повернення в меню
                back_keyboard = InlineKeyboardMarkup([[
                    InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
                ]])
                
                await query.edit_message_text("❌ База даних порожня.", reply_markup=back_keyboard)
                return
            
            # Зберігаємо результати для цього користувача
            search_results[user_id] = all_entries
            current_page[user_id] = 0
            
            if len(all_entries) <= 10:
                # Якщо записів мало, показуємо всі
                keyboard = pagination_manager.create_search_results_keyboard(all_entries, 0, user_id)
                message_text = f"📋 **Всі записи в базі**\n\nЗнайдено: {len(all_entries)} записів"
                await query.edit_message_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
            else:
                # Якщо багато записів, показуємо з пагінацією
                keyboard = pagination_manager.create_search_results_keyboard(all_entries, 0, user_id)
                page_info = pagination_manager.get_page_info(all_entries, 0)
                message_text = f"📋 **Всі записи в базі**\n\n{page_info}"
                await query.edit_message_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
        
        except Exception as e:
            logger.log_error(f"Помилка отримання списку записів: {e}", user_id)
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("❌ Помилка при отриманні списку записів.", reply_markup=back_keyboard)
        
    elif command == "admin":
        if user_id != ADMIN_USER_ID:
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("❌ У вас немає прав адміністратора.", reply_markup=back_keyboard)
            return
        
        # Виконуємо логіку адмін панелі без виклику команди
        users = auth_manager.get_allowed_users()
        
        if not users:
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("📋 **Панель адміністратора**\n\nНемає користувачів для управління.", reply_markup=back_keyboard)
            return
        
        # Створюємо клавіатуру для управління користувачами
        keyboard = auth_manager.create_users_management_keyboard(users, 0, 10, ADMIN_USER_ID)
        
        message_text = f"📋 **Панель адміністратора**\n\nКористувачі з доступом: {len(users)}\n\nНатисніть на користувача для видалення:"
        
        await query.edit_message_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
        
    elif command == "reconnect":
        if user_id != ADMIN_USER_ID:
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("❌ У вас немає прав адміністратора.", reply_markup=back_keyboard)
            return
        
        # Виконуємо логіку перепідключення без виклику команди
        keepass = get_keepass_handler()
        if not keepass:
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("❌ KeePass обробник не ініціалізований.", reply_markup=back_keyboard)
            return
        
        try:
            if keepass.force_reconnect():
                # Створюємо кнопку повернення в меню
                back_keyboard = InlineKeyboardMarkup([[
                    InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
                ]])
                
                await query.edit_message_text("✅ Перепідключення до бази даних виконано успішно!", reply_markup=back_keyboard)
                logger.log_info(f"Адміністратор {user_id} виконав перепідключення до бази даних")
            else:
                # Створюємо кнопку повернення в меню
                back_keyboard = InlineKeyboardMarkup([[
                    InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
                ]])
                
                await query.edit_message_text("❌ Помилка при перепідключенні до бази даних.", reply_markup=back_keyboard)
        except Exception as e:
            logger.log_error(f"Помилка команди перепідключення: {e}", user_id)
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("❌ Помилка при перепідключенні до бази даних.", reply_markup=back_keyboard)
        
    elif command == "help":
        if not auth_manager.is_user_allowed(user_id):
            logger.log_unauthorized_access_attempt(user_id, "menu callback help")
            # Створюємо кнопку повернення в меню
            back_keyboard = InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
            ]])
            
            await query.edit_message_text("❌ У вас немає доступу до бота.", reply_markup=back_keyboard)
            return
        
        # Показуємо довідку
        help_text = """
🤖 **KeePass Telegram Bot - Довідка**

**Основні команди:**
• `/start` - перевірка доступу та початок роботи
• `/search` - пошук записів у базі KeePass
• `/group` - пошук записів за групою
• `/list` - показати всі записи з бази
• `/help` - ця довідка

**Для адміністратора:**
• `/admin` - панель управління користувачами
• `/reconnect` - перепідключення до бази даних

**Як користуватися:**

🔍 **Пошук записів:**
1. Надішліть `/search`
2. Введіть запит для пошуку
3. Оберіть запис з результату

📁 **Пошук за групою:**
1. Надішліть `/group`
2. Введіть назву групи (наприклад: `Email`)
3. Переглядайте записи в цій групі

📋 **Список всіх записів:**
1. Надішліть `/list`
2. Переглядайте всі записи з пагінацією

**Примітки:**
• Пошук нечутливий до регістру
• Всі дії логуються для безпеки
• Для доступу потрібен пін-код (запитуйте у адміністратора)
        """
        
        # Створюємо кнопку повернення в меню
        back_keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
        ]])
        
        await query.edit_message_text(help_text, parse_mode='Markdown', reply_markup=back_keyboard)
        
    elif command == "request_access":
        # Запит доступу для неавторизованого користувача
        # Створюємо кнопку повернення в меню
        back_keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
        ]])
        
        await query.edit_message_text(
            "🔐 **Запит на доступ до бота**\n\n"
            "Для запобігання спаму введіть пін-код:\n"
            "Надішліть повідомлення з пін-кодом для отримання доступу.",
            reply_markup=back_keyboard
        )
        # Встановлюємо стан очікування пін-коду
        context.user_data['waiting_for_pin'] = True
        context.user_data['waiting_for_email_code'] = False
        
    elif command == "menu":
        # Повернення в головне меню
        keyboard = create_menu_keyboard(user_id)
        
        if auth_manager.is_user_allowed(user_id):
            # Авторизований користувач
            if user_id == ADMIN_USER_ID:
                # Адміністратор
                message_text = "👑 Ви адміністратор"
            else:
                # Звичайний користувач
                message_text = "✅ Ви маєте доступ до бота"
        else:
            # Неавторизований користувач
            message_text = "🔐 Для доступу потрібна авторизація"
        
        await query.edit_message_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
        
    else:
        # Створюємо кнопку повернення в меню
        back_keyboard = InlineKeyboardMarkup([[
            InlineKeyboardButton("🔙 Назад в меню", callback_data=csrf_manager.add_csrf_to_callback_data(user_id, "cmd_menu"))
        ]])
        
        await query.edit_message_text("❌ Невідома команда.", reply_markup=back_keyboard)


async def handle_callback_query(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Обробка callback запитів"""
    query = update.callback_query
    user_id = update.effective_user.id
    data = query.data
    
    await query.answer()
    
    # CSRF захист для callback запитів
    if "|csrf:" in data:
        # Витягуємо оригінальні дані з перевіркою CSRF
        original_data = csrf_manager.extract_callback_data(user_id, data)
        if not original_data:
            logger.log_csrf_attack(user_id, data)
            await query.edit_message_text("❌ Невірний токен безпеки. Спробуйте ще раз.")
            return
        data = original_data
    else:
        # Для старих callback без CSRF токенів
        logger.log_csrf_attack(user_id, data)
        await query.edit_message_text("❌ Помилка безпеки. Спробуйте ще раз.")
        return
    
    # Обробка callback для команд меню
    if data.startswith("cmd_"):
        await handle_menu_callback(update, context, data)
        return
    
    # Обробка callback для адміністратора (схвалення/відхилення користувачів)
    if data.startswith("approve_") or data.startswith("deny_"):
        await auth_manager.handle_admin_callback(update, context)
        return
    
    # Обробка callback для перегляду запису
    if data.startswith("e_"):
        if not auth_manager.is_user_allowed(user_id):
            logger.log_unauthorized_access_attempt(user_id, "callback перегляд запису")
            await query.edit_message_text("❌ У вас немає доступу до бота.")
            return
        
        uuid = data.split("_", 1)[1]
        
        # Валідація UUID
        uuid_validation = input_validator.validate_uuid(uuid)
        if not uuid_validation["valid"]:
            logger.log_error(f"Невірний UUID в callback: {uuid} для користувача {user_id}")
            await query.edit_message_text("❌ Невірний ідентифікатор запису.")
            return
        
        keepass = get_keepass_handler()
        
        if not keepass or not keepass.is_connected():
            await query.edit_message_text("❌ База даних KeePass недоступна.")
            return
        
        try:
            print(f"🔍 Отримуємо запис за UUID: {uuid}")
            entry = keepass.get_entry_by_uuid(uuid)
            if entry:
                print(f"✅ Запис отримано: {entry.get('title', 'без назви')}")
                formatted_entry = keepass.format_entry_for_display(entry)
                logger.log_password_view(user_id, entry.get("title", "невідома назва"))
                
                # Додаємо кнопку "Назад"
                back_keyboard = pagination_manager.create_back_keyboard(user_id)
                await query.edit_message_text(formatted_entry, parse_mode='HTML', reply_markup=back_keyboard)
            else:
                print(f"❌ Запис не знайдено за UUID: {uuid}")
                await query.edit_message_text("❌ Запис не знайдено.")
        except Exception as e:
            print(f"❌ Помилка отримання запису: {e}")
            logger.log_error(f"Помилка отримання запису: {e}", user_id)
            await query.edit_message_text("❌ Помилка при отриманні запису.")
        return
    
    # Обробка кнопки "Назад до пошуку"
    if data == "bs":
        if user_id not in search_results:
            await query.edit_message_text("❌ Немає збережених результатів пошуку.")
            return
        
        results = search_results[user_id]
        page = current_page.get(user_id, 0)
        
        keyboard = pagination_manager.create_search_results_keyboard(results, page, user_id)
        page_info = pagination_manager.get_page_info(results, page)
        
        await query.edit_message_text(
            f"🔍 **Результати пошуку**\n\n{page_info}",
            reply_markup=keyboard,
            parse_mode='Markdown'
        )
        return
    
    # Обробка пагінації
    if data.startswith("p_"):
        if user_id not in search_results:
            await query.edit_message_text("❌ Немає збережених результатів пошуку.")
            return
        
        try:
            page = int(data.split("_", 1)[1])
            results = search_results[user_id]
            
            keyboard = pagination_manager.create_search_results_keyboard(results, page, user_id)
            page_info = pagination_manager.get_page_info(results, page)
            
            # Оновлюємо поточну сторінку
            current_page[user_id] = page
            
            await query.edit_message_text(
                f"🔍 **Результати пошуку**\n\n{page_info}",
                reply_markup=keyboard,
                parse_mode='Markdown'
            )
        except (ValueError, IndexError):
            await query.answer("❌ Невірний номер сторінки.")
        return
    
    # Обробка видалення користувача
    if data.startswith("rm_"):
        if user_id != ADMIN_USER_ID:
            logger.log_unauthorized_access_attempt(user_id, "видалення користувача")
            await query.answer("❌ У вас немає прав адміністратора.")
            return
        
        try:
            target_user_id = int(data.split("_", 1)[1])
            
            # Знаходимо username користувача
            username = "невідомий"
            for user in auth_manager.get_allowed_users():
                if user["user_id"] == target_user_id:
                    username = user["username"]
                    break
            
            # Видаляємо користувача
            if auth_manager.revoke_user_access(target_user_id):
                # Логуємо адмін дію
                logger.log_admin_remove_user(user_id, target_user_id, username)
                await query.edit_message_text(f"✅ Користувач @{username} видалено з доступу.")
                
                # Повідомляємо користувача
                try:
                    await context.bot.send_message(
                        chat_id=target_user_id,
                        text="❌ Ваш доступ до бота було відкликано адміністратором."
                    )
                except Exception as e:
                    logger.log_error(f"Помилка відправки повідомлення користувачу: {e}")
            else:
                await query.answer("❌ Помилка при видаленні користувача.")
        except (ValueError, IndexError):
            await query.answer("❌ Невірний ID користувача.")
        return
    
    # Обробка навігації по користувачах
    if data.startswith("up_"):
        if user_id != ADMIN_USER_ID:
            await query.answer("❌ У вас немає прав адміністратора.")
            return
        
        try:
            page = int(data.split("_", 1)[1])
            users = auth_manager.get_allowed_users()
            
            keyboard = auth_manager.create_users_management_keyboard(users, page, 10, ADMIN_USER_ID)
            message_text = f"📋 **Панель адміністратора**\n\nКористувачі з доступом: {len(users)}\n\nНатисніть на користувача для видалення:"
            
            await query.edit_message_text(message_text, reply_markup=keyboard, parse_mode='Markdown')
        except (ValueError, IndexError):
            await query.answer("❌ Невірний номер сторінки.")
        return
    
    # Обробка кнопки "Назад до меню"
    if data == "back_to_menu":
        if user_id != ADMIN_USER_ID:
            await query.answer("❌ У вас немає прав адміністратора.")
            return
        
        await query.edit_message_text(
            "📋 **Панель адміністратора**\n\n"
            "Доступні команди:\n"
            "/admin - управління користувачами\n"
            "/search - пошук у базі KeePass\n"
            "/group - пошук за групою\n"
            "/list - показати всі записи"
        )
        return


def main() -> None:
    """Головна функція"""
    # Перевіряємо наявність необхідних змінних
    if not TELEGRAM_BOT_TOKEN:
        print("❌ TELEGRAM_BOT_TOKEN не встановлено в config.env файлі")
        return
    
    if not ADMIN_USER_ID:
        print("❌ ADMIN_USER_ID не встановлено в config.env файлі")
        return
    
    if not KEEPASS_PASSWORD:
        print("❌ KEEPASS_PASSWORD не встановлено в config.env файлі")
        return
    
    # Перевіряємо email конфігурацію
    if not all([ADMIN_EMAIL, SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD]):
        print("⚠️ Email 2FA конфігурація неповна. 2FA буде недоступний.")
        print("   Необхідні змінні: ADMIN_EMAIL, SMTP_SERVER, SMTP_USERNAME, SMTP_PASSWORD")
    else:
        print(f"✅ Email 2FA конфігурація перевірена. Admin email: {ADMIN_EMAIL}")
    
    print(f"✅ Конфігурація перевірена. Admin ID: {ADMIN_USER_ID}")
    
    # Ініціалізуємо rate limiter
    global rate_limiter
    rate_limiter = RateLimiter(
        max_pin_attempts=MAX_PIN_ATTEMPTS,
        max_twofa_attempts=MAX_2FA_ATTEMPTS,
        max_requests_per_minute=MAX_REQUESTS_PER_MINUTE,
        pin_lockout_duration=PIN_LOCKOUT_DURATION,
        twofa_lockout_duration=TWOFA_LOCKOUT_DURATION
    )
    print("✅ Rate limiter ініціалізовано")
    
    if not os.path.exists(KEEPASS_DB_PATH):
        print(f"❌ Файл бази даних {KEEPASS_DB_PATH} не знайдено")
        return
    
    # Ініціалізуємо KeePass обробник
    try:
        keepass_handler = init_keepass_handler(KEEPASS_DB_PATH, KEEPASS_PASSWORD, KEEPASS_KEY_FILE)
        # Встановлюємо інтервал перепідключення
        keepass_handler.reconnect_interval = KEEPASS_RECONNECT_INTERVAL
        print(f"✅ KeePass обробник ініціалізовано (інтервал перепідключення: {KEEPASS_RECONNECT_INTERVAL} сек)")
    except Exception as e:
        print(f"❌ Помилка ініціалізації KeePass: {e}")
        return
    
    # Створюємо додаток
    print("🔧 Створення Telegram додатку...")
    try:
        application = Application.builder().token(TELEGRAM_BOT_TOKEN).build()
        print("✅ Telegram додаток створено")
    except Exception as e:
        print(f"❌ Помилка створення додатку: {e}")
        return
    
    # Додаємо обробники команд
    print("🔧 Додавання обробників команд...")
    try:
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("menu", menu_command))
        application.add_handler(CommandHandler("search", search_command))
        application.add_handler(CommandHandler("group", group_command))
        application.add_handler(CommandHandler("list", list_command))
        application.add_handler(CommandHandler("admin", admin_command))
        application.add_handler(CommandHandler("reconnect", reconnect_command))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text_message))
        application.add_handler(CallbackQueryHandler(handle_callback_query))
        print("✅ Обробники команд додано")
    except Exception as e:
        print(f"❌ Помилка додавання обробників: {e}")
        return
    
    # Запускаємо бота
    print("🚀 Запуск бота...")
    print("💡 Бот запущено! Натисніть Ctrl+C для зупинки")
    try:
        application.run_polling(
            drop_pending_updates=True,
            allowed_updates=["message", "callback_query"]
        )
    except KeyboardInterrupt:
        print("\n🛑 Бот зупинено користувачем")
    except Exception as e:
        print(f"❌ Помилка запуску бота: {e}")
        return


if __name__ == "__main__":
    main()
