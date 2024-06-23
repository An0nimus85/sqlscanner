import argparse
import requests
import logging
import asyncio
import aiohttp
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re
import os
import tldextract

# Настройка логгирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Функция для проверки наличия SQL инъекций с использованием requests
def check_sql_injection(url, domain_folder, common_logger):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            # Поиск ключевых символов SQL в тексте страницы и атрибутах элементов
            if any(re.search(r'\'|\"|;|--|/\*', tag.get_text() + str(tag.attrs)) for tag in soup.find_all()):
                common_logger.warning(f"[!] Найден возможный признак SQL инъекции на странице: {url}")
                logger.warning(f"[!] Найден возможный признак SQL инъекции на странице: {url}")
        else:
            common_logger.error(f"[-] Ошибка при получении страницы {url}: {response.status_code}")
            logger.error(f"[-] Ошибка при получении страницы {url}: {response.status_code}")
    except requests.RequestException as e:
        common_logger.error(f"[-] Ошибка запроса {url}: {str(e)}")
        logger.error(f"[-] Ошибка запроса {url}: {str(e)}")

# Функция для проверки наличия SQL инъекций с использованием aiohttp (асинхронные запросы)
async def check_sql_injection_async(session, url, domain_folder, common_logger):
    try:
        async with session.get(url) as response:
            if response.status == 200:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                # Поиск ключевых символов SQL в тексте страницы и атрибутах элементов
                if any(re.search(r'\'|\"|;|--|/\*', tag.get_text() + str(tag.attrs)) for tag in soup.find_all()):
                    common_logger.warning(f"[!] Найден возможный признак SQL инъекции на странице: {url}")
                    logger.warning(f"[!] Найден возможный признак SQL инъекции на странице: {url}")
            else:
                common_logger.error(f"[-] Ошибка при получении страницы {url}: {response.status}")
                logger.error(f"[-] Ошибка при получении страницы {url}: {response.status}")
    except aiohttp.ClientError as e:
        common_logger.error(f"[-] Ошибка запроса {url}: {str(e)}")
        logger.error(f"[-] Ошибка запроса {url}: {str(e)}")

# Функция для создания папки для каждого поддомена и инициализации лог файлов
def setup_domain_folder(base_url):
    base_domain = tldextract.extract(base_url).domain
    if not os.path.exists(base_domain):
        os.mkdir(base_domain)
    return base_domain

# Функция для рекурсивного обхода сайта и его поддоменов с использованием requests
def crawl_site(base_url, max_depth, common_logger):
    visited_urls = set()
    queue = [(base_url, 0)]
    base_domain = setup_domain_folder(base_url)

    while queue:
        url, depth = queue.pop(0)
        if url in visited_urls or depth > max_depth:
            continue
        visited_urls.add(url)

        domain = tldextract.extract(url).domain
        domain_folder = os.path.join(base_domain, domain)
        if not os.path.exists(domain_folder):
            os.mkdir(domain_folder)

        log_file = os.path.join(domain_folder, f"{domain}_scan.log")
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        check_sql_injection(url, domain_folder, common_logger)

        try:
            response = requests.get(url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                for link in soup.find_all('a', href=True):
                    absolute_url = urljoin(url, link['href'])
                    # Проверяем, что ссылка ведет на текущий домен или поддомен
                    if is_subdomain(base_url, absolute_url) and absolute_url not in visited_urls:
                        queue.append((absolute_url, depth + 1))
            else:
                common_logger.error(f"[-] Ошибка при получении страницы {url}: {response.status_code}")
                logger.error(f"[-] Ошибка при получении страницы {url}: {response.status_code}")
        except requests.RequestException as e:
            common_logger.error(f"[-] Ошибка запроса {url}: {str(e)}")
            logger.error(f"[-] Ошибка запроса {url}: {str(e)}")

# Функция для проверки, является ли ссылка поддоменом текущего сайта
def is_subdomain(base_url, url):
    base_domain = tldextract.extract(base_url).domain
    current_domain = tldextract.extract(url).domain
    return current_domain == base_domain or current_domain.endswith(f".{base_domain}")

# Функция для рекурсивного обхода сайта и его поддоменов с использованием asyncio и aiohttp
async def crawl_site_async(base_url, max_depth, common_logger):
    visited_urls = set()
    queue = [(base_url, 0)]
    base_domain = setup_domain_folder(base_url)

    async with aiohttp.ClientSession() as session:
        while queue:
            url, depth = queue.pop(0)
            if url in visited_urls or depth > max_depth:
                continue
            visited_urls.add(url)

            domain = tldextract.extract(url).domain
            domain_folder = os.path.join(base_domain, domain)
            if not os.path.exists(domain_folder):
                os.mkdir(domain_folder)

            log_file = os.path.join(domain_folder, f"{domain}_scan.log")
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)

            await check_sql_injection_async(session, url, domain_folder, common_logger)

            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        for link in soup.find_all('a', href=True):
                            absolute_url = urljoin(url, link['href'])
                            # Проверяем, что ссылка ведет на текущий домен или поддомен
                            if is_subdomain(base_url, absolute_url) and absolute_url not in visited_urls:
                                queue.append((absolute_url, depth + 1))
                    else:
                        common_logger.error(f"[-] Ошибка при получении страницы {url}: {response.status}")
                        logger.error(f"[-] Ошибка при получении страницы {url}: {response.status}")
            except aiohttp.ClientError as e:
                common_logger.error(f"[-] Ошибка запроса {url}: {str(e)}")
                logger.error(f"[-] Ошибка запроса {url}: {str(e)}")

# Функция для парсинга аргументов командной строки
def parse_arguments():
    parser = argparse.ArgumentParser(description="Скрипт для сканирования сайтов и их поддоменов на наличие SQL инъекций.")
    parser.add_argument('url', metavar='URL', type=str, help='Начальный URL для сканирования')
    parser.add_argument('--depth', type=int, default=2, help='Максимальная глубина рекурсии сканирования (по умолчанию: 2)')
    parser.add_argument('--method', choices=['requests', 'asyncio'], default='requests', help='Метод для отправки запросов (по умолчанию: requests)')
    parser.add_argument('--logfile', type=str, default='scan.log', help='Файл для записи общего лога (по умолчанию: scan.log)')
    return parser.parse_args()

# Основная программа
if __name__ == "__main__":
    args = parse_arguments()

    # Установка общего лог-файла
    common_file_handler = logging.FileHandler(args.logfile)
    common_file_handler.setLevel(logging.INFO)
    common_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    common_file_handler.setFormatter(common_formatter)
    logger.addHandler(common_file_handler)
    common_logger = logging.getLogger('common_logger')
    common_logger.addHandler(common_file_handler)

    # Укажите начальный URL для сканирования
    start_url = args.url
    max_depth = args.depth
    method = args.method

    logger.info(f"Запуск сканирования сайта {start_url} и его поддоменов на глубину {max_depth} с использованием метода {method}")

    if method == 'requests':
        crawl_site(start_url, max_depth, common_logger)
    elif method == 'asyncio':
        asyncio.run(crawl_site_async(start_url, max_depth, common_logger))

