import time

from datetime import datetime

import re

import threading

import hashlib

from collections import deque

import requests

from bs4 import BeautifulSoup

# Constants for API endpoints (same as main)

BASE_URL = "https://www.ivasms.com"

RECEIVED_SMS_PAGE_URL = f"{BASE_URL}/portal/sms/received"

GET_SMS_RANGES_URL = f"{BASE_URL}/portal/sms/received/getsms"

GET_SMS_NUMBERS_IN_RANGE_URL = f"{BASE_URL}/portal/sms/received/getsms/number"

GET_SMS_MESSAGES_FOR_NUMBER_URL = f"{BASE_URL}/portal/sms/received/getsms/number/sms"

# Globals for SMS processing

sms_getter_stop_event = threading.Event()

reported_sms_hashes = deque(maxlen=2000)

otp_cache = {}

otp_cache_lock = threading.Lock()

# Telegram message sender function to be set by main.py

send_telegram_message = None  # Will be assigned externally

def extract_otp_from_text(text):

    match = re.search(r'\b(\d{3}[- ]?\d{3})\b', text)

    if match:

        return match.group(1).replace('-', '').replace(' ', '')

    match = re.search(r'\b(\d{4,7})\b', text)

    if match:

        return match.group(1)

    return None

def process_and_report_sms(phone_number, sender_cli, message_content, message_time_obj):
    if (datetime.utcnow() - message_time_obj).total_seconds() > 300:
        return

    sms_hash = hashlib.md5(f"{phone_number}-{message_content}".encode('utf-8')).hexdigest()
    if sms_hash in reported_sms_hashes:
        return
    reported_sms_hashes.append(sms_hash)

    print(f"[SMS Detected] Number: {phone_number}, Sender: {sender_cli}, Message: {message_content[:70]}...")

    otp_code = extract_otp_from_text(message_content)
    notification_text = f"For `{phone_number}`\nMessage: `{message_content}`\n"

    if otp_code:
        notification_text += f"OTP: `{otp_code}`\n"
        with otp_cache_lock:
            otp_cache[phone_number] = otp_code

    notification_text += "---\nMade by me 😎"

    # Safely get group chat ID from sms module
    try:
        group_chat_id = sms.GROUP_CHAT_ID_FOR_LISTS
    except AttributeError:
        group_chat_id = None

    if send_telegram_message and group_chat_id:
        send_telegram_message(notification_text, chat_id=group_chat_id)



def get_polling_csrf_token(session):

    try:

        resp = session.get(RECEIVED_SMS_PAGE_URL)

        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, 'html.parser')

        token_tag = soup.find('meta', {'name': 'csrf-token'})

        if token_tag:

            return token_tag['content']

        hidden_token = soup.find('input', {'name': '_token'})

        if hidden_token:

            return hidden_token['value']

        raise Exception("CSRF token not found on SMS received page.")

    except Exception as e:

        print(f"[!] Error getting polling CSRF token: {e}")

        return None

def _fetch_sms_ranges(session, token, headers):

    payload = {'_token': token}

    resp = session.post(GET_SMS_RANGES_URL, data=payload, headers=headers)

    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, 'html.parser')

    ranges = []

    for div in soup.find_all('div', class_='item'):

        card_body = div.find('div', class_='card-body')

        if card_body and 'onclick' in card_body.attrs:

            onclick_val = card_body['onclick']

            m = re.search(r"getDetials\('([^']+)'\)", onclick_val)

            if m:

                ranges.append(m.group(1))

    return ranges

def _fetch_numbers_in_range(session, token, headers, range_name):

    payload = {'_token': token, 'start': '', 'end': '', 'range': range_name}

    resp = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload, headers=headers)

    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, 'html.parser')

    numbers = []

    for div in soup.find_all('div', onclick=True):

        m = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)','(\d+)'\)", div['onclick'])

        if m:

            numbers.append(m.group(1))

    return numbers

def _fetch_sms_message_content(session, token, headers, phone_number, range_name):

    payload = {'_token': token, 'start': '', 'end': '', 'Number': phone_number, 'Range': range_name}

    resp = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload, headers=headers)

    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, 'html.parser')

    message_p = soup.find('p', class_='mb-0 pb-0')

    cli_span = soup.find('span', class_='badge-soft-warning', string='CLI')

    sender_cli = cli_span.find_next_sibling(string=True).strip() if cli_span and cli_span.find_next_sibling(string=True) else "N/A"

    message_content = message_p.get_text(strip=True) if message_p else ""

    return sender_cli, message_content

def start_realtime_sms_getter_polling(session):

    print("\n[*] Starting Real-time SMS Getter (Polling) monitor...")

    if send_telegram_message:

        send_telegram_message("ðŸ“¡ *SMS Getter Online*\n\nStarting to poll for new received SMS messages.", is_operational=True)

    polling_interval = 10  # seconds, per your request

    while not sms_getter_stop_event.is_set():

        try:

            token = get_polling_csrf_token(session)

            if not token:

                print("[!] Could not get fresh CSRF token for SMS polling. Retrying in 30s.")

                time.sleep(30)

                continue

            headers = {

                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',

                'Accept': 'text/html, */*; q=0.01',

                'X-Requested-With': 'XMLHttpRequest',

                'Referer': RECEIVED_SMS_PAGE_URL,

                'User-Agent': session.headers.get('User-Agent', '')

            }

            print("[*] SMS polling cycle started...")

            ranges = _fetch_sms_ranges(session, token, headers)

            if not ranges:

                print("[*] No SMS ranges found. Retrying...")

                time.sleep(polling_interval)

                continue

            for range_name in ranges:

                if sms_getter_stop_event.is_set():

                    break

                numbers = _fetch_numbers_in_range(session, token, headers, range_name)

                if not numbers:

                    print(f"[*] No numbers found in range {range_name}. Skipping...")

                    continue

                for number in numbers:

                    if sms_getter_stop_event.is_set():

                        break

                    sender_cli, message = _fetch_sms_message_content(session, token, headers, number, range_name)

                    if message:

                        process_and_report_sms(number, sender_cli, message, datetime.utcnow())

                    else:

                        print(f"[*] No message content for {number} in range {range_name}.")

            print(f"[*] SMS polling cycle complete. Sleeping {polling_interval}s.")

            time.sleep(polling_interval)

        except requests.exceptions.RequestException as e:

            print(f"[!] Network error during SMS polling: {e}")

            if send_telegram_message:

                send_telegram_message(f"âŒ *Polling Error*\nNetwork issue during SMS fetching: `{e}`. Retrying in 30 seconds.")

            time.sleep(30)

        except Exception as e:

            print(f"[!!!] Critical error in SMS polling loop: {e}")

            if send_telegram_message:

                send_telegram_message(f"âŒ *Polling Error*\nUnexpected error during SMS fetching: `{e}`. Retrying in 30 seconds.")

            time.sleep(30)

    print("[*] SMS Getter polling thread stopped gracefully.")




