import requests

from bs4 import BeautifulSoup

import time

import threading

import signal

import sys

import re

import sms  # import the sms module

from sms import (

    RECEIVED_SMS_PAGE_URL,

    GET_SMS_RANGES_URL,

    GET_SMS_NUMBERS_IN_RANGE_URL,

    GET_SMS_MESSAGES_FOR_NUMBER_URL,

    extract_otp_from_text,

    otp_cache,

    otp_cache_lock,

    sms_getter_stop_event,

    start_realtime_sms_getter_polling,

)



# --- Configuration ---

BOT_NAME = "Ivory Coast Numbers"

EMAIL = "aliubusayofl.or@gmail.com"

PASSWORD = "Aliumicheal23"

MAGIC_RECAPTCHA_TOKEN = "09ANMylNCxCsR-EALV_dP3Uu9rxSkQG-0xTH4zhiWAwivWepExAlRqCrvuEUPLATuySMYLrpy9fmeab6yOPTYLcHu8ryQ2sf3mkJCsRhoVj6IOkQDcIdLm49TAGADj_M6K"

TELEGRAM_BOT_TOKEN = "8022869076:AAE70p_mPgNPSC-K8ZgsYZ-wUIpMWKdj7jI"

GROUP_CHAT_ID_FOR_LISTS = "-1002962530930"

DM_CHAT_ID = "7864059689"

BASE_URL = "https://www.ivasms.com"

LOGIN_URL = f"{BASE_URL}/login"

# Pass group chat ID to sms module
sms.GROUP_CHAT_ID_FOR_LISTS = GROUP_CHAT_ID_FOR_LISTS


SMS_HISTORY_PAGE_URL = f"{BASE_URL}/portal/sms/test/sms?app=WhatsApp"

SMS_HISTORY_API_URL = f"{BASE_URL}/portal/sms/test/sms"

TEST_NUMBERS_PAGE_URL = f"{BASE_URL}/portal/numbers/test"

TEST_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/test"

ADD_NUMBER_API_URL = f"{BASE_URL}/portal/numbers/termination/number/add"

MY_NUMBERS_URL = f"{BASE_URL}/portal/live/my_sms"

GET_NUMBER_LIST_API_URL = f"{BASE_URL}/portal/live/getNumbers"

REMOVE_ALL_NUMBERS_API_URL = f"{BASE_URL}/portal/numbers/return/allnumber/bluck"

# Globals

current_session = None

api_csrf_token = None

# Acquisition state

acquisition_pending = False

pending_number_info = None

pending_user_id = None

user_misuse_counts = {}

ADMIN_USERNAMES = ["FXCNUMBERSadmin", "admin2", "bills_gang", "admin4"]

# Proxy rotation helper

class ProxyRotator:

    def __init__(self, proxies):

        self.proxies = proxies

        self.index = 0

        self.lock = threading.Lock()

    def get_next_proxy(self):

        with self.lock:

            proxy = self.proxies[self.index]

            self.index = (self.index + 1) % len(self.proxies)

            return proxy

def create_session_with_proxy(proxy_str):

    session = requests.Session()

    proxy_url = f"http://{proxy_str}"

    session.proxies.update({

        "http": proxy_url,

        "https": proxy_url,

    })

    session.headers.update({'User-Agent': 'Mozilla/5.0 (Android 11; Mobile; rv:128.0) Gecko/128.0 Firefox/128.0'})

    return session

def send_telegram_message(chat_id, text, is_operational=False):

    if is_operational:

        text += f"\n\nðŸ¤– _{BOT_NAME}_"

    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': 'Markdown'}

    try:

        resp = requests.post(api_url, json=payload, timeout=10)

        resp.raise_for_status()

        print(f"[TG] Sent to {chat_id}: \"{text[:70].replace(chr(10), ' ')}...\"")

    except Exception as e:

        print(f"[!] TELEGRAM ERROR: Failed to send to {chat_id}: {e}")

# Assign telegram message sender to sms module

sms.send_telegram_message = lambda text, **kwargs: send_telegram_message(DM_CHAT_ID, text, **kwargs)

# --- Functions from your original code, adjusted to accept session ---

def acquire_and_process_number(session, number_range_name, phone_number_to_process):

    global api_csrf_token

    print(f"\n--- Acquiring Number: {phone_number_to_process} ---")

    try:

        # Rotate proxy for CSRF fetch if needed here (optional)

        page_response = session.get(TEST_NUMBERS_PAGE_URL)

        page_response.raise_for_status()

        soup = BeautifulSoup(page_response.text, 'html.parser')

        token_tag = soup.find('meta', {'name': 'csrf-token'})

        if not token_tag:

            raise Exception("Could not find CSRF token on TEST_NUMBERS_PAGE_URL for acquisition.")

        api_csrf_token = token_tag['content']

        print(f"[+] Acquired API CSRF Token for acquisition: {api_csrf_token}")

        params = {

            'draw': '1',

            'columns[0][data]': 'range',

            'columns[1][data]': 'test_number',

            'columns[2][data]': 'term',

            'columns[3][data]': 'P2P',

            'columns[4][data]': 'A2P',

            'columns[5][data]': 'Limit_Range',

            'columns[6][data]': 'limit_cli_a2p',

            'columns[7][data]': 'limit_did_a2p',

            'columns[8][data]': 'limit_cli_did_a2p',

            'columns[9][data]': 'limit_cli_p2p',

            'columns[10][data]': 'limit_did_p2p',

            'columns[11][data]': 'limit_cli_did_p2p',

            'columns[12][data]': 'updated_at',

            'columns[13][data]': 'action',

            'columns[13][searchable]': 'false',

            'columns[13][orderable]': 'false',

            'order[0][column]': '1',

            'order[0][dir]': 'asc',

            'start': '0',

            'length': '50',

            'search[value]': phone_number_to_process,

            '_': int(time.time() * 1000),

        }

        search_headers = {

            'Accept': 'application/json, text/javascript, */*; q=0.01',

            'Referer': TEST_NUMBERS_PAGE_URL,

            'X-CSRF-TOKEN': api_csrf_token,

            'X-Requested-With': 'XMLHttpRequest',

            'User-Agent': session.headers['User-Agent']

        }

        search_response = session.get(TEST_NUMBERS_API_URL, params=params, headers=search_headers)

        search_response.raise_for_status()

        search_data = search_response.json()

        if not search_data.get('data'):

            print(f"[!] Number {phone_number_to_process} not found or taken.")

            return False

        found_number_id = search_data['data'][0].get('id')

        if not found_number_id:

            print(f"[!] No ID found for number {phone_number_to_process}.")

            return False

        print(f"[+] Found Termination ID: {found_number_id}")

        add_payload = {'_token': api_csrf_token, 'id': found_number_id}

        add_headers = search_headers.copy()

        add_headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8'

        add_headers['Accept'] = 'application/json'

        add_response = session.post(ADD_NUMBER_API_URL, data=add_payload, headers=add_headers)

        print(f"[DEBUG] Add number response status: {add_response.status_code}")

        print(f"[DEBUG] Add number response text: {add_response.text[:300]}")

        add_data = add_response.json()

        if "done" in add_data.get("message", "").lower():

            print("[SUCCESS] Number added successfully.")

            send_telegram_message(DM_CHAT_ID, f"âœ… *Number Added*\n\nSuccessfully added `{phone_number_to_process}`.", is_operational=True)

            get_and_send_number_list(session, found_number_id, api_csrf_token, number_range_name)

            otp_thread = threading.Thread(target=realtime_otp_fetcher, args=(session, phone_number_to_process, number_range_name), daemon=True)

            otp_thread.start()

            return True

        else:

            error_msg = add_data.get("message", "Unknown error")

            print(f"[!] Add failed: {error_msg}")

            send_telegram_message(DM_CHAT_ID, f"âŒ *Add Failed*\n\nCould not add `{phone_number_to_process}`. Reason: `{error_msg}`", is_operational=True)

            return False

    except Exception as e:

        print(f"[!] Error acquiring number {phone_number_to_process}: {e}")

        send_telegram_message(DM_CHAT_ID, f"âŒ *Acquisition Error*\n\nError: `{e}`", is_operational=True)

        return False

def get_and_send_number_list(session, termination_id, current_api_csrf_token, range_name):

    print("\n--- Fetching Full Number List ---")

    try:

        payload = {'termination_id': termination_id, '_token': current_api_csrf_token}

        headers = {

            'Accept': '*/*',

            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',

            'Referer': MY_NUMBERS_URL,

            'X-CSRF-TOKEN': current_api_csrf_token,

            'X-Requested-With': 'XMLHttpRequest',

            'User-Agent': session.headers['User-Agent']

        }

        resp = session.post(GET_NUMBER_LIST_API_URL, data=payload, headers=headers)

        resp.raise_for_status()

        numbers_data = resp.json()

        if numbers_data and isinstance(numbers_data, list):

            number_list_str = "\n".join([f"`{item.get('Number', 'N/A')}`" for item in numbers_data])

            message_text = f"**New Asset Package Acquired: {range_name}**\n\n_{len(numbers_data)} items available:_\n{number_list_str}"

            send_telegram_message(GROUP_CHAT_ID_FOR_LISTS, message_text)

    except Exception as e:

        print(f"[!] Error fetching number list: {e}")

def realtime_otp_fetcher(session, phone_number_to_watch, acquired_range_name):

    print(f"\n--- Real-time OTP Fetcher for {phone_number_to_watch} (Range: {acquired_range_name}) ---")

    send_telegram_message(DM_CHAT_ID,

                          f"ðŸ‘€ *Real-time OTP Watch*\n\nMonitoring for a code on acquired number:\n`{phone_number_to_watch}` (Range: `{acquired_range_name}`)\nThis will continue until you stop the script (Ctrl+C).",

                          is_operational=True)

    while not sms.sms_getter_stop_event.is_set():

        try:

            resp = session.get(RECEIVED_SMS_PAGE_URL)

            resp.raise_for_status()

            soup = BeautifulSoup(resp.text, 'html.parser')

            token_tag = soup.find('meta', {'name': 'csrf-token'})

            current_otp_csrf_token = token_tag['content'] if token_tag else None

            if not current_otp_csrf_token:

                hidden_token = soup.find('input', {'name': '_token'})

                current_otp_csrf_token = hidden_token['value'] if hidden_token else None

            if not current_otp_csrf_token:

                raise Exception("CSRF token missing on OTP fetch page")

            headers = {

                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',

                'Accept': 'text/html, */*; q=0.01',

                'X-Requested-With': 'XMLHttpRequest',

                'Referer': RECEIVED_SMS_PAGE_URL,

                'User-Agent': session.headers['User-Agent']

            }

            payload_ranges = {'_token': current_otp_csrf_token}

            resp_ranges = session.post(GET_SMS_RANGES_URL, data=payload_ranges, headers=headers)

            resp_ranges.raise_for_status()

            payload_numbers = {'_token': current_otp_csrf_token, 'start': '', 'end': '', 'range': acquired_range_name}

            resp_numbers = session.post(GET_SMS_NUMBERS_IN_RANGE_URL, data=payload_numbers, headers=headers)

            resp_numbers.raise_for_status()

            soup_numbers = BeautifulSoup(resp_numbers.text, 'html.parser')

            target_div = None

            for div in soup_numbers.find_all('div', onclick=True):

                onclick_val = div['onclick']

                m = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)','(\d+)'\)", onclick_val)

                if m and m.group(1) == phone_number_to_watch:

                    target_div = div

                    break

            if not target_div:

                print(f"[*] Number {phone_number_to_watch} not visible yet. Retrying in 10s...")

                time.sleep(10)

                continue

            m = re.search(r"getDetialsNumber[A-Za-z0-9]+\('(\d+)','(\d+)'\)", target_div['onclick'])

            if not m:

                print(f"[!] Could not parse onclick for {phone_number_to_watch}. Retrying in 10s...")

                time.sleep(10)

                continue

            extracted_number_id = m.group(1)

            payload_sms = {

                '_token': current_otp_csrf_token,

                'start': '',

                'end': '',

                'Number': extracted_number_id,

                'Range': acquired_range_name

            }

            resp_sms = session.post(GET_SMS_MESSAGES_FOR_NUMBER_URL, data=payload_sms, headers=headers)

            resp_sms.raise_for_status()

            soup_sms = BeautifulSoup(resp_sms.text, 'html.parser')

            message_div = soup_sms.find('div', class_='Message')

            whatsapp_code = None

            if message_div:

                message_content = message_div.get_text(strip=True)

                print(f"[*] OTP Fetcher Message content: {message_content}")

                whatsapp_code = sms.extract_otp_from_text(message_content)

            if whatsapp_code:

                print(f"\n[SUCCESS] OTP Intercepted: {whatsapp_code}")

                notification = f"âœ… *OTP Acquired! (Real-time Fetch)*\n\n*Number:* `{phone_number_to_watch}`\n*OTP:* `{whatsapp_code}`"

                send_telegram_message(DM_CHAT_ID, notification, is_operational=True)

                with sms.otp_cache_lock:

                    sms.otp_cache[phone_number_to_watch] = whatsapp_code

                return True

            else:

                print(f"[*] OTP not found yet for {phone_number_to_watch}. Retrying in 10s...")

            time.sleep(10)

        except requests.exceptions.RequestException as e:

            print(f"[!] Network error during OTP fetch: {e}")

            send_telegram_message(DM_CHAT_ID, f"âš ï¸ *Network Error (OTP Fetch)*\n\nCould not fetch OTP for `{phone_number_to_watch}`: `{e}`. Retrying in 30s.", is_operational=True)

            time.sleep(30)

        except Exception as e:

            print(f"[!] General error during OTP fetch: {e}")

            send_telegram_message(DM_CHAT_ID, f"âŒ *OTP Fetch Error*\n\nError fetching OTP for `{phone_number_to_watch}`: `{e}`. Retrying in 30s.", is_operational=True)

            time.sleep(30)

def prompt_account_cleanup(session):

    send_telegram_message(DM_CHAT_ID, "Do you want to perform account cleanup? Reply with 'y' or 'n'.")

    while True:

        answer = input("Cleanup? (y/n): ").strip().lower()

        if answer == 'y':

            success = clear_all_existing_numbers(session)

            if success:

                send_telegram_message(DM_CHAT_ID, "âœ… Account cleanup completed.", is_operational=True)

            else:

                send_telegram_message(DM_CHAT_ID, "No numbers to clean or cleanup failed.", is_operational=True)

            break

        elif answer == 'n':

            send_telegram_message(DM_CHAT_ID, "Account cleanup skipped as per your choice.", is_operational=True)

            break

        else:

            print("Please reply with 'y' or 'n'.")

def clear_all_existing_numbers(session):

    global api_csrf_token

    print("\n[*] Performing account cleanup...")

    try:

        page_response = session.get(TEST_NUMBERS_PAGE_URL)

        page_response.raise_for_status()

        soup = BeautifulSoup(page_response.text, 'html.parser')

        token = soup.find('meta', {'name': 'csrf-token'})

        if not token:

            print("[!] Could not find CSRF token for cleanup. Skipping cleanup.")

            return False

        api_csrf_token = token['content']

        headers = {

            'Accept': '*/*',

            'X-CSRF-TOKEN': api_csrf_token,

            'X-Requested-With': 'XMLHttpRequest',

            'Referer': MY_NUMBERS_URL

        }

        response = session.post(REMOVE_ALL_NUMBERS_API_URL, headers=headers)

        response.raise_for_status()

        if "NumberDone" in response.text:

            print("[SUCCESS] Account cleanup complete.")

            return True

        else:

            print("[*] No existing numbers to clean up.")

            return False

    except Exception as e:

        print(f"[!] Could not perform cleanup: {e}")

        return False

def telegram_listener_task(session):

    global acquisition_pending, pending_number_info, pending_user_id

    print("[*] Starting Telegram Group Assistant...")

    offset = None

    api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

    while not sms.sms_getter_stop_event.is_set():

        try:

            params = {"timeout": 30, "offset": offset, "allowed_updates": ["message"]}

            resp = requests.get(f"{api_url}/getUpdates", params=params, timeout=35)

            resp.raise_for_status()

            updates = resp.json()["result"]

            for update in updates:

                offset = update["update_id"] + 1

                if "message" not in update:

                    continue

                msg = update.get("message", {})

                chat = msg.get("chat", {})

                user = msg.get("from", {})

                text = msg.get("text", "").strip()

                chat_id = chat.get("id")

                is_group = chat.get("type", "").endswith("group")

                username = user.get("username", user.get("first_name", "User"))

                user_id = user.get("id")

                def playful_warning():

                    count = user_misuse_counts.get(user_id, 0) + 1

                    user_misuse_counts[user_id] = count

                    if count == 1:

                        send_telegram_message(chat_id, "Ole ðŸ˜‚ðŸ’” you are not allowed to use me like that ðŸ¤ªðŸ˜œðŸ˜›ðŸ˜‹ you self go do juju ðŸ¤ªðŸ’”")

                    else:

                        send_telegram_message(chat_id, "walai if you do that again I go remove you ðŸ˜‚ I just dey play ni Sha")

                if text == "/start1":

                    if username not in ADMIN_USERNAMES:

                        playful_warning()

                        continue

                    try:

                        params_feed = {

                            'app': 'WhatsApp', 'draw': '1',

                            'columns[0][data]': 'range', 'columns[0][orderable]': 'false',

                            'columns[1][data]': 'termination.test_number', 'columns[1][searchable]': 'false', 'columns[1][orderable]': 'false',

                            'columns[2][data]': 'originator', 'columns[2][orderable]': 'false',

                            'columns[3][data]': 'messagedata', 'columns[3][orderable]': 'false',

                            'columns[4][data]': 'senttime', 'columns[4][searchable]': 'false',

                            'order[0][column]': '4', 'order[0][dir]': 'desc',

                            'start': '0', 'length': '25', 'search[value]': '',

                            '_': int(time.time() * 1000),

                        }

                        headers_feed = {

                            'Accept': 'application/json, text/javascript, */*; q=0.01',

                            'Referer': SMS_HISTORY_PAGE_URL,

                            'X-Requested-With': 'XMLHttpRequest',

                            'User-Agent': session.headers['User-Agent']

                        }

                        api_response = session.get(SMS_HISTORY_API_URL, params=params_feed, headers=headers_feed)

                        api_response.raise_for_status()

                        data = api_response.json()

                        for message in data.get('data', []):

                            phone_number_html = message.get('termination', {}).get('test_number', '')

                            full_number = BeautifulSoup(phone_number_html, 'html.parser').get_text(strip=True)

                            range_name = message.get('range', 'Unknown')

                            if full_number:

                                acquisition_pending = True

                                pending_number_info = (range_name, full_number)

                                pending_user_id = user_id

                                prompt_text = f"Do you want to acquire this number {range_name}?\nNumber: `{full_number}`\nReply with 'y' or 'n'."

                                send_telegram_message(chat_id, prompt_text)

                                break

                        else:

                            send_telegram_message(chat_id, "No available numbers found to acquire at this time.")

                    except Exception as e:

                        send_telegram_message(chat_id, f"Error fetching live numbers: {e}")

                    continue

                if text == "/next":

                    if username not in ADMIN_USERNAMES:

                        playful_warning()

                        continue

                    send_telegram_message(chat_id, "Fetching next available number...")

                    try:

                        page_response = session.get(TEST_NUMBERS_PAGE_URL)

                        page_response.raise_for_status()

                        soup = BeautifulSoup(page_response.text, 'html.parser')

                        token_tag = soup.find('meta', {'name': 'csrf-token'})

                        if not token_tag:

                            send_telegram_message(chat_id, "âŒ Could not get CSRF token to fetch numbers.")

                            continue

                        fresh_token = token_tag['content']

                        params_search = {

                            'draw': '1',

                            'columns[0][data]': 'range',

                            'columns[1][data]': 'test_number',

                            'columns[2][data]': 'term',

                            'columns[3][data]': 'P2P',

                            'columns[4][data]': 'A2P',

                            'order[0][column]': '1',

                            'order[0][dir]': 'asc',

                            'start': '0',

                            'length': '1',

                            'search[value]': '',

                            '_': int(time.time() * 1000),

                        }

                        headers_search = {

                            'Accept': 'application/json, text/javascript, */*; q=0.01',

                            'Referer': TEST_NUMBERS_PAGE_URL,

                            'X-CSRF-TOKEN': fresh_token,

                            'X-Requested-With': 'XMLHttpRequest',

                            'User-Agent': session.headers['User-Agent']

                        }

                        search_response = session.get(TEST_NUMBERS_API_URL, params=params_search, headers=headers_search)

                        search_response.raise_for_status()

                        data = search_response.json()

                        if not data.get('data'):

                            send_telegram_message(chat_id, "âŒ No available numbers found right now.")

                            continue

                        first_item = data['data'][0]

                        range_name = first_item.get('range', 'Unknown')

                        full_number = first_item.get('test_number') or first_item.get('Number')

                        if not full_number:

                            send_telegram_message(chat_id, "âŒ Could not find a valid number in search results.")

                            continue

                        acquisition_pending = True

                        pending_number_info = (range_name, full_number)

                        pending_user_id = user_id

                        prompt_text = f"Do you want to acquire this number {range_name}?\nNumber: `{full_number}`\nReply with 'y' or 'n'."

                        send_telegram_message(chat_id, prompt_text)

                    except Exception as e:

                        send_telegram_message(chat_id, f"Error fetching numbers: {e}")

                    continue

                if acquisition_pending and is_group and user_id == pending_user_id and text.lower() in ['y', 'n']:

                    range_name, full_number = pending_number_info

                    if text.lower() == 'y':

                        send_telegram_message(chat_id, f"Acquiring number `{full_number}` from {range_name}...")

                        success = acquire_and_process_number(session, range_name, full_number)

                        if success:

                            send_telegram_message(chat_id, f"âœ… Number `{full_number}` successfully acquired and OTP watcher started.")

                        else:

                            send_telegram_message(chat_id, f"âŒ Failed to acquire number `{full_number}`.")

                    else:

                        send_telegram_message(chat_id, "Okay, skipping this number. Waiting for next target...")

                    acquisition_pending = False

                    pending_number_info = None

                    pending_user_id = None

                    continue

                if text == "/stop":

                    if username not in ADMIN_USERNAMES:

                        playful_warning()

                        continue

                    sms.sms_getter_stop_event.set()

                    send_telegram_message(chat_id, "Boss ðŸ˜’ man have stopped the bot")

                    continue

                if is_group and text.lower() == "werey" and username in ADMIN_USERNAMES:

                    send_telegram_message(chat_id, "odeh shebi nah you create me and I dey abuse you")

                    continue

                if text in ["/search", "/start1", "/next", "/stop"] and username not in ADMIN_USERNAMES:

                    playful_warning()

                    continue

                if is_group and text.isdigit() and len(text) > 8:

                    print(f"--- On-Demand Code Check for {text} requested by @{username} in chat {chat_id} ---")

                    with sms.otp_cache_lock:

                        cached_otp = sms.otp_cache.get(text)

                    if cached_otp:

                        reply = f"âœ… @{username}, cached code for `{text}` is: `{cached_otp}`"

                        send_telegram_message(chat_id, reply)

                        continue

                    params_sms_history = {'app': 'WhatsApp', 'search[value]': text, '_': int(time.time() * 1000)}

                    headers_sms_history = {

                        'Accept': 'application/json, text/javascript, */*; q=0.01',

                        'Referer': SMS_HISTORY_PAGE_URL,

                        'X-Requested-With': 'XMLHttpRequest'

                    }

                    api_resp = session.get(SMS_HISTORY_API_URL, params=params_sms_history, headers=headers_sms_history)

                    api_resp.raise_for_status()

                    data_sms = api_resp.json()

                    reply = f"âŒ @{username}, code not received for `{text}`"

                    if data_sms.get('data'):

                        for sms_entry in data_sms['data']:

                            sms_number_html = sms_entry.get('termination', {}).get('test_number', '')

                            sms_number = BeautifulSoup(sms_number_html, 'html.parser').get_text(strip=True)

                            if sms_number == text:

                                message_data = sms_entry.get('messagedata', '')

                                otp_code = sms.extract_otp_from_text(message_data)

                                if otp_code:

                                    reply = f"âœ… @{username}, code for `{text}` is: `{otp_code}`"

                                    with sms.otp_cache_lock:

                                        sms.otp_cache[text] = otp_code

                                    break

                    send_telegram_message(chat_id, reply)

        except requests.exceptions.RequestException as e:

            print(f"[!!!] Network error in Telegram Listener thread: {e}")

            time.sleep(10)

        except Exception as e:

            print(f"[!!!] CRITICAL ERROR in Telegram Listener thread: {e}")

            time.sleep(10)

def remove_all_numbers_on_exit(signum, frame):

    print("\n\n[!!!] Shutdown signal detected (Ctrl+C). Initiating cleanup sequence.")

    send_telegram_message(DM_CHAT_ID, "ðŸ›‘ *Shutdown Signal Detected*\n\nAttempting graceful shutdown...", is_operational=True)

    if not current_session:

        sys.exit(1)

    sms.sms_getter_stop_event.set()

    time.sleep(2)

    if clear_all_existing_numbers(current_session):

        send_telegram_message(DM_CHAT_ID, "âœ… *Shutdown Complete*\n\nAll temporary numbers removed. Bot is offline.", is_operational=True)

    else:

        send_telegram_message(DM_CHAT_ID, "âœ… *Shutdown Complete*\n\nBot is offline (no numbers to remove or cleanup failed).", is_operational=True)

    print("[*] Exiting now.")

    sys.exit(0)

def main():

    global current_session

    signal.signal(signal.SIGINT, remove_all_numbers_on_exit)

    # Load proxies from file and split into batches of 100 per bot

    with open("proxies.txt") as f:

        all_proxies = [line.strip() for line in f if line.strip()]

    # For this bot, pick first 100 proxies (adjust as needed)

    my_proxies = all_proxies[:100]

    proxy_rotator = ProxyRotator(my_proxies)

    # Create initial session with first proxy

    proxy_str = proxy_rotator.get_next_proxy()

    session = create_session_with_proxy(proxy_str)

    current_session = session

    try:

        # Step 1: Authenticate

        print("\n[*] Authenticating...")

        login_page = session.get(LOGIN_URL)

        login_page.raise_for_status()

        soup = BeautifulSoup(login_page.text, 'html.parser')

        csrf_token_input = soup.find('input', {'name': '_token'})

        if not csrf_token_input:

            raise Exception("CSRF token not found on login page")

        csrf_token = csrf_token_input['value']

        login_payload = {

            '_token': csrf_token,

            'email': EMAIL,

            'password': PASSWORD,

            'g-recaptcha-response': MAGIC_RECAPTCHA_TOKEN,

            'submit': 'Log in'

        }

        login_resp = session.post(LOGIN_URL, data=login_payload, headers={'Referer': LOGIN_URL})

        login_resp.raise_for_status()

        if "login" not in login_resp.url and "Logout" in login_resp.text:

            print("[SUCCESS] Authentication complete!")

            send_telegram_message(DM_CHAT_ID, "ðŸ” *Authentication Successful*\n\nSession established.", is_operational=True)

            # Prompt for cleanup

            prompt_account_cleanup(session)

            # Start Telegram listener thread

            telegram_thread = threading.Thread(target=telegram_listener_task, args=(session,), daemon=True)

            telegram_thread.start()

            # Start SMS polling thread

            sms_thread = threading.Thread(target=sms.start_realtime_sms_getter_polling, args=(session,), daemon=True)

            sms_thread.start()

            print("\n[SUCCESS] Bot is fully operational.")

            print("   > Telegram Listener running in background.")

            print("   > Real-time SMS Getter running in background.")

            print("   > Use /start1 in group (admin only) to start acquisition prompt.")

            print("   > Use /next to get next batch (admin only).")

            print("   > Use /stop to stop the bot (admin only).")

            # Keep main thread alive

            while True:

                time.sleep(1)

        else:

            print("\n[!!!] AUTHENTICATION FAILED. Check credentials or recaptcha token.")

            send_telegram_message(DM_CHAT_ID, "âŒ *Authentication Failed*\n\nLogin rejected. Update `MAGIC_RECAPTCHA_TOKEN` or check credentials.", is_operational=True)

    except Exception as e:

        print(f"[!!!] Critical startup error: {e}")

        send_telegram_message(DM_CHAT_ID, f"âŒ *Bot Startup Error*\n\nCritical error: `{e}`. Bot shutting down.", is_operational=True)

if __name__ == "__main__":

    main()
