import logging
import os
import re
from dotenv import load_dotenv
load_dotenv()
import paramiko
import psycopg2
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext, ConversationHandler
from psycopg2 import sql

# Настройка логгирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.DEBUG
)
logger = logging.getLogger(__name__)

# Загрузка переменных окружения
TOKEN = os.getenv("TOKEN")
hostname = os.getenv("RM_HOST")
username = os.getenv("RM_USER")
password = os.getenv("RM_PASSWORD")
db_user = os.getenv("DB_USER")
db_password = os.getenv("DB_PASSWORD")
db_name = os.getenv("DB_DATABASE")
db_host = os.getenv("DB_HOST")

# Функция приветствия
def start(update: Update, context: CallbackContext) -> None:
    update.message.reply_text('Привет! Я бот для поиска email-адресов и номеров телефонов.')

# Функция поиска email
def find_email(update, context) -> None:
    update.message.reply_text('Отправьте текст, в котором нужно найти email-адреса.')
    return 'search_emails'

def search_emails(update, context):
    text = update.message.text
    emails = find_emails(text)
    if emails:
        message = f"Найденные email-адреса: {', '.join(emails)}\nХотите добавить их в базу данных? (Да/Нет)"
        update.message.reply_text(message)
        context.user_data['emails'] = emails
        return 'prompt_add_emails'
    else:
        update.message.reply_text("Email-адреса не найдены.")
        return ConversationHandler.END

# Функция записи email в базу данных
def write_emails_to_database(emails):
    flag = False
    try:
        connection = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host
        )
        cursor = connection.cursor()
        for email in emails:
            cursor.execute("INSERT INTO email (mail) VALUES (%s)", (email,))
        connection.commit()
        logger.info("Emails successfully inserted into the database.")
        flag = True
    except (Exception, psycopg2.Error) as error:
        logger.error("Error while connecting to PostgreSQL", error)
    finally:
        if connection:
            cursor.close()
            connection.close()
            logger.info("PostgreSQL connection is closed.")
    return flag

# Функция поиска номеров телефонов
def find_phone_number(update: Update, context: CallbackContext) -> None:
    update.message.reply_text('Отправьте текст, в котором нужно найти номера телефонов.')
    return "search_phone_numbers"


def search_phone_numbers(update, context):
    text = update.message.text
    phone_numbers = find_phone_numbers(text)
    if phone_numbers:
        message = f"Найденные номера телефонов: {', '.join(phone_numbers)}\nХотите добавить их в базу данных? (Да/Нет)"
        update.message.reply_text(message)
        context.user_data['phone_numbers'] = phone_numbers
        return 'prompt_add_phone_numbers'
    else:
        update.message.reply_text("Номера телефонов не найдены.")
        return ConversationHandler.END

# Функция записи номеров телефонов в базу данных
def write_phone_numbers_to_database(phone_numbers):
    try:
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host
        )
        cur = conn.cursor()
        for number in phone_numbers:
            cur.execute("INSERT INTO phone (phone_number) VALUES (%s)", (number,))
        conn.commit()
        cur.close()
        conn.close()
        return True
    except psycopg2.Error as e:
        print("Error while connecting to PostgreSQL:", e)
        return False

# Функция проверки сложности пароля
def verify_password(update, context):
    update.message.reply_text('Введите пароль для проверки его сложности.')
    return 'check_password'

# Функция подключения по SSH
def ssh_connect(hostname, username, password):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=hostname, username=username, password=password)
    return ssh

# Функция выполнения команды на удаленном хосте
def run_command(ssh, command):
    stdin, stdout, stderr = ssh.exec_command(command)
    return stdout.readlines()

# Функция закрытия SSH-соединения
def close_ssh(ssh):
    ssh.close()

# Функция получения информации о диске
def get_df_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    df_info = run_command(ssh, "df -h")
    close_ssh(ssh)
    update.message.reply_text("".join(df_info))

# Функция получения свободной памяти
def get_free_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    free_info = run_command(ssh, "free -m")
    close_ssh(ssh)
    update.message.reply_text("".join(free_info))

# Функция получения информации о процессоре
def get_mpstat_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    mpstat_info = run_command(ssh, "mpstat")
    close_ssh(ssh)
    update.message.reply_text("".join(mpstat_info))

# Функция получения информации о пользователях
def get_w_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    w_info = run_command(ssh, "w")
    close_ssh(ssh)
    update.message.reply_text("".join(w_info))

# Функция получения информации о последних авторизациях
def get_auths_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    auths_info = run_command(ssh, "last -n 10")
    close_ssh(ssh)
    update.message.reply_text("".join(auths_info))

# Функция получения критической информации из syslog
def get_critical_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    critical_info = run_command(ssh, "tail -n 5 /var/log/syslog | grep 'CRITICAL'")
    close_ssh(ssh)
    update.message.reply_text("".join(critical_info))

# Функция получения информации о процессах
def get_ps_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    ps_info = run_command(ssh, "ps a")
    close_ssh(ssh)
    update.message.reply_text("".join(ps_info))

# Функция получения информации о сетевых соединениях
def get_ss_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    ss_info = run_command(ssh, "ss -tuln")
    close_ssh(ssh)
    update.message.reply_text("".join(ss_info))

# Функция получения списка установленных пакетов
def get_apt_list_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    apt_list_info = run_command(ssh, "dpkg -l | head -10")
    close_ssh(ssh)
    update.message.reply_text("".join(apt_list_info))

# Функция получения списка сервисов
def get_services_info(update, context):
    ssh = ssh_connect(hostname, username, password)
    services_info = run_command(ssh, "systemctl list-units --type=service | head -10")
    close_ssh(ssh)
    update.message.reply_text("".join(services_info))

# Функция поиска email в тексте
def find_emails(text: str) -> list:
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return re.findall(pattern, text)

# Функция поиска номеров телефонов в тексте
def find_phone_numbers(text: str) -> list:
    pattern = r'(?:(?:\+7|8)[\s-]?)?\(?\d{3}\)?[\s-]?\d{1}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}'
    return re.findall(pattern, text)

# Функция проверки сложности пароля
def check_password_complexity(update, context):
    password = update.message.text
    if re.match(r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#$%^&*()])[A-Za-z\d!@#$%^&*()]{8,}$', password):
        update.message.reply_text('Пароль сложный.')
    else:
        update.message.reply_text('Пароль простой.')
    return ConversationHandler.END

# Функция для чтения логов репликации
def get_replication_logs() -> str:
    log_file_path = '/var/log/postgresql/postgresql.log'
    try:
        with open(log_file_path, 'r') as file:
            logs = file.readlines()

        replication_logs = [log for log in logs if 'replication' in log]
        if not replication_logs:
            return "Логи репликации не найдены."

        # Возвращаем только первые 10 строк логов репликации
        return "".join(replication_logs[:10])
    except FileNotFoundError:
        logger.error("Log file not found.")
        return "Файл логов не найден."
    except Exception as e:
        logger.error("Error while reading the log file.", exc_info=e)
        return "Произошла ошибка при чтении файла логов."

# Функция обработки команды /get_repl_logs в Telegram-боте
def get_repl_logs(update: Update, context: CallbackContext) -> None:
    logs = get_replication_logs()

    # Разбиение сообщения на части, если оно слишком длинное
    MAX_MESSAGE_LENGTH = 4096
    for i in range(0, len(logs), MAX_MESSAGE_LENGTH):
        update.message.reply_text(logs[i:i + MAX_MESSAGE_LENGTH])

# Функция получения email-адресов из базы данных
def get_emails(update: Update, context: CallbackContext) -> None:
    try:
        connection = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host
        )
        cursor = connection.cursor()
        cursor.execute("SELECT mail FROM email")
        emails = cursor.fetchall()
        email_list = [email[0] for email in emails]
        update.message.reply_text("Email-адреса: " + ", ".join(email_list))
    except (Exception, psycopg2.Error) as error:
        logger.error("Error while connecting to PostgreSQL", error)
    finally:
        if connection:
            cursor.close()
            connection.close()
# Функция получения номеров телефонов из базы данных
def get_phone_numbers(update: Update, context: CallbackContext) -> None:
    try:
        connection = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host
        )
        cursor = connection.cursor()
        cursor.execute("SELECT phone_number FROM phone")
        phone_numbers = cursor.fetchall()
        phone_list = [number[0] for number in phone_numbers]
        update.message.reply_text("Номера телефонов: " + ", ".join(phone_list))
    except (Exception, psycopg2.Error) as error:
        logger.error("Error while connecting to PostgreSQL", error)
    finally:
        if connection:
            cursor.close()
            connection.close()

# Функция обработки ответа пользователя о добавлении email в базу данных
def prompt_to_add_emails(update, context):
    user_reply = update.message.text.lower()
    emails = context.user_data.get('emails')
    if user_reply == 'да':
        if emails and write_emails_to_database(emails):
            update.message.reply_text("Email-адреса успешно добавлены в базу данных.")
        else:
            update.message.reply_text("Произошла ошибка при добавлении email-адресов в базу данных.")
    else:
        update.message.reply_text("Операция отменена.")
    return ConversationHandler.END


# Функция обработки ответа пользователя о добавлении номеров телефонов в базу данных
def prompt_to_add_phone_numbers(update, context):
    user_reply = update.message.text.lower()
    phone_numbers = context.user_data.get('phone_numbers')
    if user_reply == 'да':
        if phone_numbers and write_phone_numbers_to_database(phone_numbers):
            update.message.reply_text("Номера телефонов успешно добавлены в базу данных.")
        else:
            update.message.reply_text("Произошла ошибка при добавлении номеров телефонов в базу данных.")
    else:
        update.message.reply_text("Операция отменена.")
    return ConversationHandler.END

# Функция запуска бота
def main() -> None:
    updater = Updater(TOKEN)  # Исправленная строка
    dispatcher = updater.dispatcher

    conv_handler_add_phone_numbers_to_database = ConversationHandler(
        entry_points=[CommandHandler("find_phone_number", find_phone_number)],
        states={
            'search_phone_numbers': [MessageHandler(Filters.text & ~Filters.command, search_phone_numbers)],
            'prompt_add_phone_numbers': [MessageHandler(Filters.text & ~Filters.command, prompt_to_add_phone_numbers)],
        },
        fallbacks=[]
    )

    conv_handler_add_emails_to_database = ConversationHandler(
        entry_points=[CommandHandler("find_email", find_email)],
        states={
             'search_emails': [MessageHandler(Filters.text & ~Filters.command, search_emails)],
             'prompt_add_emails': [MessageHandler(Filters.text & ~Filters.command, prompt_to_add_emails)]
        },
        fallbacks=[]
    )

    conv_handler_verify_password = ConversationHandler(
        entry_points=[CommandHandler("verify_password", verify_password)],
        states={
             'check_password': [MessageHandler(Filters.text & ~Filters.command, check_password_complexity)],
        },
        fallbacks=[]
    )

    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(CommandHandler("get_df", get_df_info))
    dispatcher.add_handler(CommandHandler("get_free", get_free_info))
    dispatcher.add_handler(CommandHandler("get_mpstat", get_mpstat_info))
    dispatcher.add_handler(CommandHandler("get_w", get_w_info))
    dispatcher.add_handler(CommandHandler("get_auths", get_auths_info))
    dispatcher.add_handler(CommandHandler("get_critical", get_critical_info))
    dispatcher.add_handler(CommandHandler("get_ps", get_ps_info))
    dispatcher.add_handler(CommandHandler("get_ss", get_ss_info))
    dispatcher.add_handler(CommandHandler("get_apt_list", get_apt_list_info))
    dispatcher.add_handler(CommandHandler("get_services", get_services_info))
    dispatcher.add_handler(CommandHandler("get_repl_logs", get_repl_logs))
    dispatcher.add_handler(CommandHandler("get_emails", get_emails))
    dispatcher.add_handler(CommandHandler("get_phone_numbers", get_phone_numbers))

    dispatcher.add_handler(conv_handler_add_phone_numbers_to_database)
    dispatcher.add_handler(conv_handler_add_emails_to_database)
    dispatcher.add_handler(conv_handler_verify_password)
    updater.start_polling()
    logger.info("Бот запущен.")
    updater.idle()

if __name__ == '__main__':
    main()
