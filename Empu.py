import requests
import json
import time
from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3
import random
import string
import re
import uuid
import os
from urllib.parse import urlparse, parse_qs
import asyncio
from playwright.async_api import async_playwright
import traceback
import base64

# Konfigurasi
CAPTCHA_API_KEY = "2CAPCTHA"
BASE_URL = "https://www.b402.ai"
AUTH_BASE_URL = "https://auth.b402.ai"
SITEKEY = "0x4AAAAAAB5QdBYvpAN8f8ZI"
MAIL_TM_API = "https://api.mail.tm"

# OAuth Config
MAX_TURNSTILE_RETRY = 3
DISCORD_CLIENT_ID = "1268496937149591707"
DISCORD_REDIRECT_URI = "https://www.b402.ai/api/api/v1/channel/discord/callback"
DISCORD_SCOPE = "identify%20guilds"
DISCORD_RESPONSE_TYPE = "code"
DISCORD_CREDENTIALS_FILE = "discord_credentials.txt"

TWITTER_CLIENT_ID = "T0hnQWU1b0FfZVhCSEpPSFNobE0tREo6MTpjaQ"
TWITTER_REDIRECT_URI = "https://www.b402.ai/api/api/v1/channel/twitter/callback"
TWITTER_SCOPE = "tweet.read%20users.read%20follows.read%20like.read%20list.read"
TWITTER_RESPONSE_TYPE = "code"
TWITTER_CREDENTIALS_FILE = "twitter_credentials.txt"

ACCOUNTS_FILE = "accounts.json"
PRIVATE_KEYS_FILE = "privkey.txt"
MAX_WALLETS_PER_ACCOUNT = 1
MAX_TWITTER_LINK_RETRY = 3
MAX_DISCORD_LINK_RETRY = 3
MAX_TURNSTILE_RETRIES = 3

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    BOLD = '\033[1m'
    ENDC = '\033[0m'

    @staticmethod
    def info(text):
        return f"{Colors.OKCYAN}{text}{Colors.ENDC}"

    @staticmethod
    def success(text):
        return f"{Colors.OKGREEN}{text}{Colors.ENDC}"

    @staticmethod
    def warning(text):
        return f"{Colors.WARNING}{text}{Colors.ENDC}"

    @staticmethod
    def error(text):
        return f"{Colors.FAIL}{text}{Colors.ENDC}"

    @staticmethod
    def bold(text):
        return f"{Colors.BOLD}{text}{Colors.ENDC}"


def generate_random_string(length=10):
    letters = string.ascii_letters + string.digits
    return ''.join(random.choice(letters) for _ in range(length))


def generate_random_email():
    username = generate_random_string(10)
    domain = random.choice(["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"])
    return f"{username}@{domain}"


def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(length))


def generate_wallet():
    acct = Account.create()
    return acct.address, acct.key.hex()


def sign_message(private_key, message):
    w3 = Web3()
    message_hash = encode_defunct(text=message)
    signed_message = w3.eth.account.sign_message(message_hash, private_key=private_key)
    return signed_message.signature.hex()


def solve_captcha_turnstile(sitekey, url):
    try:
        session = requests.Session()

        create_task_payload = {
            "clientKey": CAPTCHA_API_KEY,
            "task": {
                "type": "TurnstileTaskProxyless",
                "websiteURL": url,
                "websiteKey": sitekey
            }
        }

        create_task_response = session.post(
            "https://api.2captcha.com/createTask",
            json=create_task_payload,
            timeout=60
        )

        create_task_response.raise_for_status()
        task_data = create_task_response.json()

        if not task_data.get("errorId") == 0:
            print(Colors.error(f"  ❌ Gagal nggawe tugas captcha: {task_data}"))
            return None

        task_id = task_data.get("taskId")
        if not task_id:
            print(Colors.error("  ❌ Ora entuk taskId saka 2captcha"))
            return None

        print(Colors.info("  ⏳ Ngenteni 2captcha ngrampungke Turnstile..."))

        get_result_payload = {
            "clientKey": CAPTCHA_API_KEY,
            "taskId": task_id
        }

        start_time = time.time()
        while True:
            result_response = session.post(
                "https://api.2captcha.com/getTaskResult",
                json=get_result_payload,
                timeout=60
            )

            result_response.raise_for_status()
            result_data = result_response.json()

            if result_data.get("status") == "ready":
                solution = result_data.get("solution", {}).get("token")
                if solution:
                    print(Colors.success("  ✅ Captcha Turnstile rampung!"))
                    return solution
                else:
                    print(Colors.error("  ❌ Ora entuk token solusi Turnstile"))
                    return None
            elif result_data.get("status") == "processing":
                if time.time() - start_time > 120:
                    print(Colors.error("  ❌ Wektune ngenteni captcha kadaluwarsa"))
                    return None
                time.sleep(5)
            else:
                print(Colors.error(f"  ❌ Error seko 2captcha, jan bosok: {result_data}"))
                return None

    except Exception as e:
        print(Colors.error(f"  ❌ Error solve_captcha_turnstile: {str(e)}"))
        return None


class FingerprintGenerator:
    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
    ]

    @staticmethod
    def generate():
        return {
            "user_agent": random.choice(FingerprintGenerator.USER_AGENTS),
            "device_id": str(uuid.uuid4()),
            "session_id": str(uuid.uuid4()),
            "screen_width": random.choice([1920, 1600, 1536, 1440, 1366]),
            "screen_height": random.choice([1080, 900, 864, 900, 768]),
            "timezone_offset": random.choice([-420, -360, -300, 0, 60, 120, 180, 420]),
            "language": random.choice(["en-US", "en-GB", "id-ID"]),
            "platform": random.choice(["Win32", "MacIntel", "Linux x86_64"]),
            "webgl_vendor": random.choice([
                "Google Inc. (NVIDIA)",
                "Google Inc. (Intel)",
                "Google Inc. (AMD)"
            ]),
            "webgl_renderer": random.choice([
                "ANGLE (NVIDIA, NVIDIA GeForce GTX 1050 Ti Direct3D11 vs_5_0 ps_5_0)",
                "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0)",
                "ANGLE (AMD, Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0)"
            ])
        }


class MailTMService:
    def __init__(self):
        self.base_url = MAIL_TM_API
        self.session = requests.Session()
        self.token = None
        self.email = None
        self.password = None

    def generate_email(self):
        try:
            domains_response = self.session.get(f"{self.base_url}/domains")
            domains_response.raise_for_status()
            domains = domains_response.json().get("hydra:member", [])

            if not domains:
                return None, None, None

            domain = random.choice(domains)
            username = generate_random_string(10).lower()
            address = f"{username}@{domain['domain']}"

            password = generate_password(12)

            account_payload = {
                "address": address,
                "password": password
            }

            account_response = self.session.post(f"{self.base_url}/accounts", json=account_payload)
            account_response.raise_for_status()
            account_data = account_response.json()

            token_payload = {
                "address": address,
                "password": password
            }

            token_response = self.session.post(f"{self.base_url}/token", json=token_payload)
            token_response.raise_for_status()
            token_data = token_response.json()

            self.token = token_data.get("token")
            self.email = address
            self.password = password

            print(Colors.success(f"  ✅ Email sementara digawe: {address}"))
            return address, password, self.token

        except Exception as e:
            print(Colors.error(f"  ❌ Gagal nggawe email sementara: {str(e)}"))
            return None, None, None

    def get_email_address(self):
        if not self.email:
            self.generate_email()
        return self.email, self.password, self.token

    def wait_for_message(self, subject_contains=None, timeout=120):
        if not self.token:
            return None

        headers = {"Authorization": f"Bearer {self.token}"}
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                messages_response = self.session.get(f"{self.base_url}/messages", headers=headers)
                messages_response.raise_for_status()
                messages_data = messages_response.json()

                for msg in messages_data.get("hydra:member", []):
                    if subject_contains:
                        if subject_contains.lower() in msg.get("subject", "").lower():
                            return msg
                    else:
                        return msg

                time.sleep(5)
            except Exception as e:
                print(Colors.error(f"  ❌ Error ngenteni email: {str(e)}"))
                time.sleep(5)

        print(Colors.error("  ❌ Ora ana email mlebu (timeout)"))
        return None

    def get_message_content(self, msg_id):
        if not self.token:
            return None

        headers = {"Authorization": f"Bearer {self.token}"}
        try:
            msg_response = self.session.get(f"{self.base_url}/messages/{msg_id}", headers=headers)
            msg_response.raise_for_status()
            msg_data = msg_response.json()
            return msg_data
        except Exception as e:
            print(Colors.error(f"  ❌ Error njupuk isi email: {str(e)}"))
            return None

    def get_verification_link(self, subject_contains=None, link_contains=None, timeout=120):
        msg = self.wait_for_message(subject_contains=subject_contains, timeout=timeout)
        if not msg:
            return None

        msg_content = self.get_message_content(msg.get("id"))
        if not msg_content:
            return None

        html = msg_content.get("html", [])
        text = msg_content.get("text", "")

        content = ""
        if html:
            if isinstance(html, list):
                content = "\n".join(html)
            else:
                content = html
        else:
            content = text

        links = re.findall(r'https?://[^\s\'"<>]+', content)

        if link_contains:
            for link in links:
                if link_contains in link:
                    return link

        return links[0] if links else None


class B402Tools:
    def __init__(self):
        self.fingerprint = FingerprintGenerator.generate()
        self.session = requests.Session()
        self.headers = self._generate_headers()
        self.web3 = Web3()
        self.mail_service = MailTMService()
        self.debug_info = []
        self.private_keys = self.load_private_keys()

    def _generate_headers(self, with_auth=False, jwt=None):
        ua = self.fingerprint['user_agent']
        headers = {
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "cache-control": "no-cache",
            "content-type": "application/json",
            "origin": "https://www.b402.ai",
            "pragma": "no-cache",
            "priority": "u=1, i",
            "referer": "https://www.b402.ai/",
            "sec-ch-ua": "\"Chromium\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": ua,
            "x-fingerprint": self.fingerprint['device_id']
        }

        if with_auth and jwt:
            headers["authorization"] = f"Bearer {jwt}"

        return headers

    def log_debug(self, key, value):
        self.debug_info.append({key: value})
        print(Colors.info(f"  [DEBUG] {key}: {value}"))

    def save_accounts(self, accounts):
        try:
            with open(ACCOUNTS_FILE, "w") as f:
                json.dump(accounts, f, indent=2)
        except Exception as e:
            print(Colors.error(f"  ❌ Gagal nyimpen akun: {str(e)}"))

    def load_accounts(self):
        if not os.path.exists(ACCOUNTS_FILE):
            return []

        try:
            with open(ACCOUNTS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            print(Colors.error(f"  ❌ Gagal muat akun: {str(e)}"))
            return []

    def load_private_keys(self):
        if not os.path.exists(PRIVATE_KEYS_FILE):
            return []

        try:
            with open(PRIVATE_KEYS_FILE, "r") as f:
                keys = [line.strip() for line in f if line.strip()]
                return keys
        except Exception as e:
            print(Colors.error(f"  ❌ gagal muat private key: {str(e)}"))
            return []

    def register_account(self, email, password):
        url = f"{AUTH_BASE_URL}/api/auth/register"
        payload = {
            "email": email,
            "password": password,
            "fingerprint": self.fingerprint['device_id']
        }

        try:
            response = self.session.post(url, headers=self.headers, json=payload)
            data = response.json()

            if response.status_code == 201:
                print(Colors.success("  ✅ Registrasi sukses"))
                return True
            else:
                print(Colors.error(f"  ❌ Registrasi gagal: {data}"))
                return False
        except Exception as e:
            print(Colors.error(f"  ❌ Error registrasi: {str(e)}"))
            return False

    def login_account(self, email, password):
        url = f"{AUTH_BASE_URL}/api/auth/login"
        payload = {
            "email": email,
            "password": password,
            "fingerprint": self.fingerprint['device_id']
        }

        try:
            response = self.session.post(url, headers=self.headers, json=payload)
            data = response.json()

            if response.status_code == 200:
                jwt = data.get("data", {}).get("accessToken")
                print(Colors.success("  ✅ Login sukses"))
                return jwt
            else:
                print(Colors.error(f"  ❌ Login gagal bajingan: {data}"))
                return None
        except Exception as e:
            print(Colors.error(f"  ❌ Error login bajingan: {str(e)}"))
            return None

    def verify_email(self, verification_link):
        try:
            response = self.session.get(verification_link, headers=self.headers, allow_redirects=False)

            if response.status_code in [302, 301]:
                location = response.headers.get("Location", "")
                print(Colors.success("  ✅ Email verifikasi sukses bolo"))
                return True
            else:
                print(Colors.error(f"  ❌ Verifikasi email gagal: {response.status_code}"))
                return False
        except Exception as e:
            print(Colors.error(f"  ❌ Error verifikasi email: {str(e)}"))
            return False

    def get_turnstile_token_with_playwright(self, wallet_address):
        async def solve():
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context(user_agent=self.fingerprint['user_agent'])
                    page = await context.new_page()

                    url = "https://www.b402.ai"
                    await page.goto(url)

                    await page.wait_for_timeout(5000)

                    frames = page.frames
                    turnstile_token = None

                    for frame in frames:
                        try:
                            cf_ch = await frame.evaluate("""() => {
                                const el = document.getElementById("cf-chl-widget");
                                return el ? el.getAttribute("data-cf-chl-widget-id") : null;
                            }""")
                        except:
                            cf_ch = None

                        if cf_ch:
                            try:
                                widget_frame = frame.child_frames[0]
                                await widget_frame.wait_for_selector("input[type='checkbox']", timeout=15000)
                                await widget_frame.click("input[type='checkbox']")
                                await page.wait_for_timeout(10000)
                            except:
                                pass

                    local_storage = await page.evaluate("() => JSON.stringify(window.localStorage)")
                    self.log_debug("LocalStorage", local_storage)

                    cookies = await context.cookies()
                    self.log_debug("Cookies", cookies)

                    turnstile_token = await page.evaluate(
                        """() => {
                            const cfToken = document.querySelector('input[name="cf-turnstile-response"]');
                            return cfToken ? cfToken.value : null;
                        }"""
                    )

                    await browser.close()
                    return turnstile_token

            except Exception as e:
                print(Colors.error(f"  ❌ Error Playwright: {str(e)}"))
                return None

        turnstile_token = asyncio.run(solve())

        if not turnstile_token:
            print(Colors.warning("  ⚠️ Gagal njupuk token Turnstile via Playwright, nyoba 2captcha..."))
            turnstile_token = solve_captcha_turnstile(SITEKEY, "https://www.b402.ai")

        return turnstile_token

    def get_turnstile_token(self, wallet_address):
        for attempt in range(1, MAX_TURNSTILE_RETRIES + 1):
            print(Colors.info(f"  🔄 Nyoba njupuk Turnstile token (attempt {attempt}/{MAX_TURNSTILE_RETRIES})..."))
            token = self.get_turnstile_token_with_playwright(wallet_address)
            if token:
                return token
            time.sleep(3)

        print(Colors.error("  ❌ Gagal njupuk Turnstile token, wes nyobo ping patang puluh patang!"))
        return None

    def get_challenge(self, wallet_address, turnstile_token, lid, client_id):
        url = f"{BASE_URL}/api/api/v1/auth/web3/challenge"
        payload = {
            "walletType": "evm",
            "walletAddress": wallet_address,
            "turnstileToken": turnstile_token,
            "lid": lid,
            "clientId": client_id
        }

        self.log_debug("LID (UUID v4)", lid)

        try:
            response = self.session.post(url, headers=self.headers, json=payload)

            if response.status_code != 200:
                print(Colors.error(f"  ❌ Gagal njupuk challenge: {response.status_code}"))
                try:
                    print(Colors.error(f"  🔍 Respon: {response.json()}"))
                except:
                    print(Colors.error(f"  🔍 Respon teks: {response.text[:300]}"))
                return None

            data = response.json()
            challenge = data.get("data", {}).get("challenge")

            if not challenge:
                print(Colors.error("  ❌ Ora oleh challenge seko server"))
                return None

            print(Colors.success("  ✅ Challenge ketemu gan!"))
            return challenge

        except Exception as e:
            print(Colors.error(f"  ❌ Error get_challenge: {str(e)}"))
            return None

    def complete_challenge(self, wallet_address, signature, lid, client_id):
        url = f"{BASE_URL}/api/api/v1/auth/web3/verify"
        payload = {
            "walletType": "evm",
            "walletAddress": wallet_address,
            "signature": signature,
            "lid": lid,
            "clientId": client_id
        }

        try:
            response = self.session.post(url, headers=self.headers, json=payload)
            data = response.json()

            if response.status_code == 200:
                jwt = data.get("data", {}).get("token")
                print(Colors.success("  ✅ Web3 login sukses"))
                return jwt
            else:
                print(Colors.error(f"  ❌ Web3 login gagal: {data}"))
                return None

        except Exception as e:
            print(Colors.error(f"  ❌ Error complete_challenge: {str(e)}"))
            return None

    def get_wallet_nonce(self, wallet_address, jwt):
        url = f"{BASE_URL}/api/api/v1/wallet/nonce"
        headers = self._generate_headers(with_auth=True, jwt=jwt)
        params = {
            "walletAddress": wallet_address
        }

        try:
            response = self.session.get(url, headers=headers, params=params)
            data = response.json()

            if response.status_code == 200:
                nonce = data.get("data", {}).get("nonce")
                print(Colors.success(f"  ✅ Entuk wallet nonce: {nonce}"))
                return nonce
            else:
                print(Colors.error(f"  ❌ Gagal njupuk wallet nonce: {data}"))
                return None

        except Exception as e:
            print(Colors.error(f"  ❌ Error get_wallet_nonce: {str(e)}"))
            return None

    def connect_wallet(self, jwt, wallet_address, signature, nonce):
        url = f"{BASE_URL}/api/api/v1/wallet/connect"
        headers = self._generate_headers(with_auth=True, jwt=jwt)
        payload = {
            "walletType": "evm",
            "walletAddress": wallet_address,
            "signature": signature,
            "nonce": nonce
        }

        try:
            response = self.session.post(url, headers=headers, json=payload)
            data = response.json()

            if response.status_code == 200:
                print(Colors.success("  ✅ Wallet kasambung karo akun"))
                return True
            else:
                print(Colors.error(f"  ❌ Gagal nyambungake wallet: {data}"))
                return False

        except Exception as e:
            print(Colors.error(f"  ❌ Error connect_wallet: {str(e)}"))
            return False

    def create_account_flow(self):
        email, email_password, email_token = self.mail_service.get_email_address()
        if not email:
            print(Colors.error("  ❌ Gagal nggawe email, batal nggawe akun wae, malesi"))
            return False

        password = generate_password(12)
        wallet_address, private_key = generate_wallet()

        print(Colors.info(f"  📧 Email: {email}"))
        print(Colors.info(f"  🔑 Password: {password}"))
        print(Colors.info(f"  💼 Wallet: {wallet_address}"))
        print(Colors.info(f"  🔐 Private Key: {private_key}"))

        registered = self.register_account(email, password)
        if not registered:
            return False

        verification_link = self.mail_service.get_verification_link(
            subject_contains="Verify your email",
            link_contains="b402"
        )

        if not verification_link:
            print(Colors.error("  ❌ Gagal njupuk link verifikasi email"))
            return False

        verified = self.verify_email(verification_link)
        if not verified:
            return False

        jwt = self.login_account(email, password)
        if not jwt:
            return False

        turnstile_token = self.get_turnstile_token(wallet_address)
        if not turnstile_token:
            return False

        lid = str(uuid.uuid4())
        client_id = self.fingerprint['device_id']

        challenge = self.get_challenge(wallet_address, turnstile_token, lid, client_id)
        if not challenge:
            return False

        signature = sign_message(private_key, challenge)

        jwt_web3 = self.complete_challenge(wallet_address, signature, lid, client_id)
        if not jwt_web3:
            return False

        nonce = self.get_wallet_nonce(wallet_address, jwt_web3)
        if nonce is None:
            return False

        connect_signature = sign_message(private_key, nonce)

        connected = self.connect_wallet(jwt_web3, wallet_address, connect_signature, nonce)
        if not connected:
            return False

        accounts = self.load_accounts()

        account_data = {
            "email": email,
            "password": password,
            "wallet_address": wallet_address,
            "private_key": private_key,
            "jwt": jwt_web3,
            "fingerprint": self.fingerprint,
            "created_at": time.time()
        }

        accounts.append(account_data)
        self.save_accounts(accounts)

        print(Colors.success("  ✅ Akun anyar kasimpen ning accounts.json\n"))
        return True

    def get_jwt_for_account(self, account):
        email = account.get("email")
        password = account.get("password")

        jwt = self.login_account(email, password)
        return jwt

    def check_and_refresh_token(self, account, index):
        jwt = account.get("jwt")

        if jwt:
            url = f"{BASE_URL}/api/api/v1/profile"
            headers = self._generate_headers(with_auth=True, jwt=jwt)

            try:
                response = self.session.get(url, headers=headers)

                if response.status_code == 200:
                    return account
                else:
                    print(Colors.warning("  ⚠️ Token lawas kadaluwarsa, nyoba login maneh bolo..."))
            except:
                print(Colors.warning("  ⚠️ Gagal verifikasi token lawas, nyoba login maneh bolo..."))

        email = account.get("email")
        password = account.get("password")

        if not email or not password:
            print(Colors.error("  ❌ Ora anaono data email/password ggo akun iki"))
            return None

        jwt = self.login_account(email, password)
        if not jwt:
            print(Colors.error("  ❌ Gagal refreshing token nggo akun iki"))
            return None

        account["jwt"] = jwt

        accounts = self.load_accounts()
        if 0 <= index < len(accounts):
            accounts[index] = account
            self.save_accounts(accounts)

        return account

    def get_profile_and_suggestions(self, jwt):
        url = f"{BASE_URL}/api/api/v1/assistant/chat"
        headers = self._generate_headers(with_auth=True, jwt=jwt)
        payload = {
            "message": "Check my progress and tell me what I should do next.",
            "channel": "b402-dashboard"
        }

        try:
            response = self.session.post(url, headers=headers, json=payload)
            data = response.json()

            if response.status_code == 200:
                return data
            else:
                print(Colors.error(f"  ❌ Gagal njupuk progres: {data}"))
                return None
        except Exception as e:
            print(Colors.error(f"  ❌ Error get_profile_and_suggestions: {str(e)}"))
            return None

    def parse_progress(self, chat_response):
        try:
            suggestions = chat_response.get("data", {}).get("suggestions", [])
            message = chat_response.get("data", {}).get("message", "")

            progress = {
                "wallet_connected": True,
                "twitter_connected": False,
                "discord_connected": False,
                "can_claim_box": False,
                "next_actions": []
            }

            needs_twitter = False
            needs_discord = False
            can_claim_box = False

            for suggestion in suggestions:
                label = suggestion.get('label', '').lower()
                action = suggestion.get('action', '').lower()

                if 'twitter' in label or 'connect twitter' in label or 'connect x' in label or 'x (twitter)' in label:
                    needs_twitter = True

                if 'discord' in label or 'connect discord' in label:
                    needs_discord = True

                if 'mystery box' in label or 'claim box' in label or 'mint' in label:
                    can_claim_box = True

            progress = {
                'message': message,
                'wallet_connected': True,
                'twitter_connected': not needs_twitter,
                'discord_connected': not needs_discord,
                'can_claim_box': can_claim_box,
                'next_actions': []
            }

            for suggestion in suggestions:
                progress['next_actions'].append({
                    'type': suggestion.get('type', ''),
                    'label': suggestion.get('label', ''),
                    'action': suggestion.get('action', '')
                })

            return progress
        except Exception as e:
            print(Colors.error(f"  ❌ Error parse_progress: {str(e)}"))
            return None

    def _mint_once(self, jwt, endpoint_path, payload=None):
        """Mint sepisan nganggo endpoint custom."""
        try:
            if endpoint_path.startswith("http"):
                url = endpoint_path
            else:
                url = f"{BASE_URL}{endpoint_path}"

            headers = self._generate_headers(with_auth=True, jwt=jwt)
            if payload is None:
                payload = {}

            resp = self.session.post(url, headers=headers, json=payload)
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}

            return resp.status_code, data
        except Exception as e:
            return 0, {"error": str(e)}

    def spam_mint_box_flow(self):
        """Spam mint kanggo kabeh akun seko accounts.json tanpa jeda antar mint."""
        print(f"\n{Colors.info('  📂 Ngeload akun seko accounts.json...')}")
        accounts = self.load_accounts()

        if not accounts:
            print(Colors.error("  ❌ Ora ana akun sing ketemu!"))
            print(Colors.info("  💡 Gawe dhisik akun nggo menu [1] utawa impor nganggo [5]."))
            return

        print(Colors.success(f"  ✓ Ketemu {len(accounts)} akun\n"))

        endpoint_path = input(
            Colors.info("  🧩 Lebokne neng path endpoint mint (contone: /api/api/v1/mystery-box/mint): ")
        ).strip()
        if not endpoint_path:
            print(Colors.error("  ❌ Endpoint kopong, ora iso diteruske."))
            return

        try:
            max_mint = int(
                input(
                    Colors.info("  🔁 meh piro saben akun? (conto: 2 opo 3): ")
                ).strip()
            )
        except ValueError:
            print(Colors.error("  ❌ Leboken angka sing bener nggo jumlah mint yo."))
            return

        print()
        total_sukses = 0
        total_gagal = 0

        for idx, account in enumerate(accounts, 1):
            print(f"  {Colors.bold('='*50)}")
            print(
                Colors.bold(
                    f"  [{idx}/{len(accounts)}] SPAM MINT kanggo wallet, gas spam!! "
                    f"{account['wallet_address'][:10]}...{account['wallet_address'][-8:]}"
                )
            )
            print(f"  {Colors.bold('='*50)}")

            account = self.check_and_refresh_token(account, idx - 1)
            if not account:
                print(Colors.error("  ❌ Ora iso otentikasi akun iki, skip wae, rajelas tenan!"))
                total_gagal += max_mint
                print()
                continue

            jwt = account["jwt"]

            sukses_akun = 0
            gagal_akun = 0

            for n in range(1, max_mint + 1):
                print(
                    Colors.info(
                        f"  🔄 Mint #{n} nggo wallet "
                        f"{account['wallet_address'][:10]}...{account['wallet_address'][-8:]}"
                    ),
                    end=" ",
                    flush=True,
                )

                status_code, data = self._mint_once(jwt, endpoint_path)

                if status_code == 200:
                    print(Colors.success("✅"))
                    sukses_akun += 1
                    total_sukses += 1
                else:
                    print(Colors.error("❌"))
                    msg = str(data)[:160]
                    print(Colors.warning(f"     ⚠️ Status: {status_code}, respon: {msg}"))
                    gagal_akun += 1
                    total_gagal += 1

            print()
            print(Colors.bold("  📊 Ringkesan akun iki:"))
            print(Colors.success(f"     ✅ Sukses mint bolo : {sukses_akun}"))
            print(Colors.error(f"     ❌ Gagal mint ngentot : {gagal_akun}"))
            print()

        print(f"\n  {Colors.bold('='*50)}")
        print(Colors.bold("  📊 RINGKESANE SPAM MINT"))
        print(f"  {Colors.bold('='*50)}")
        print(Colors.success(f"  ✅ Total mint sing sukses : {total_sukses}"))
        print(Colors.error(f"  ❌ Total mint sing gagal  : {total_gagal}"))
        print(f"  {Colors.bold('='*50)}")

    def check_status_and_progress(self):
        print(f"\n{Colors.info('  📂 nunggu sek accounts...')}")
        accounts = self.load_accounts()

        if not accounts:
            print(Colors.error("  ❌ ra ono akunmu su!"))
            print(Colors.info("  💡 gawe akun nggo option [1]."))
            return

        print(Colors.success(f"  ✓ Found {len(accounts)} accounts\n"))

        for idx, account in enumerate(accounts, 1):
            print(f"  {Colors.bold('='*50)}")
            print(Colors.bold(f"  Account {idx}/{len(accounts)}"))
            print(f"  {Colors.bold('='*50)}")

            email = account.get("email")
            wallet_address = account.get("wallet_address")

            print(Colors.info(f"  📧 Email : {email}"))
            print(Colors.info(f"  💼 Wallet: {wallet_address}"))

            account = self.check_and_refresh_token(account, idx - 1)
            if not account:
                print(Colors.error("  ❌ skip akun iki, ra jelas tenan! (cannot refresh token)"))
                print()
                continue

            jwt = account.get("jwt")

            chat_response = self.get_profile_and_suggestions(jwt)
            if not chat_response:
                print(Colors.error("  ❌ raiso jipuk data seko server, server e bosok! mending server roblox"))
                print()
                continue

            print(Colors.success("✅"))
            print()

            progress = self.parse_progress(chat_response)

            if progress:
                if not progress['twitter_connected']:
                    current_step = "🐦 Connect Twitter (X)"
                    step_emoji = "🔴"

                elif not progress['discord_connected']:
                    current_step = "💬 Connect Discord"
                    step_emoji = "🟡"

                elif progress['can_claim_box']:
                    current_step = "🎁 Claim/Mint Mystery Box"
                    step_emoji = "🟢"
                else:
                    current_step = "✅ Probably all set (no clear next action)"
                    step_emoji = "🟢"

                print(Colors.bold("  🎯 Summary:"))
                print(Colors.info(f"  {step_emoji} Current priority: {current_step}"))
                print()

                print(Colors.bold("  📌 Next Actions (from Assistant):"))
                for i, action in enumerate(progress['next_actions'], 1):
                    label = action.get('label', 'No label')
                    act = action.get('action', 'No action')
                    print(Colors.info(f"   {i}. {label} -> {act}"))

                print()

            time.sleep(1)

        print(f"  {Colors.bold('='*50)}")
        print(Colors.bold("  ✅ Done nge-check kabeh akun"))
        print(f"  {Colors.bold('='*50)}")

    def connect_twitter_flow(self):
        print(f"\n{Colors.info('  📂 nunggu sek...')}")
        accounts = self.load_accounts()

        if not accounts:
            print(Colors.error("  ❌ raono akunmu su!"))
            print(Colors.info("  💡 gawe akun sik nggo option [1]."))
            return

        print(Colors.success(f"  ✓ ketemu! {len(accounts)} accounts\n"))

        credentials = self.load_twitter_credentials()
        if not credentials:
            print(Colors.error("  ❌ raono Twitter credentials ning twitter_credentials.txt"))
            print(Colors.info("  💡 cobo gawe o file twitter_credentials.txt nggo format:"))
            print(Colors.info("     email,password"))
            return

        for idx, account in enumerate(accounts, 1):
            print(f"  {Colors.bold('='*50)}")
            print(Colors.bold(f"  Account {idx}/{len(accounts)}"))
            print(f"  {Colors.bold('='*50)}")

            email = account.get("email")
            wallet_address = account.get("wallet_address")

            print(Colors.info(f"  📧 B402 Email : {email}"))
            print(Colors.info(f"  💼 Wallet     : {wallet_address}"))

            account = self.check_and_refresh_token(account, idx - 1)
            if not account:
                print(Colors.error("  ❌ Skip akun iki, ra jelas! (cannot refresh token)"))
                print()
                continue

            jwt = account.get("jwt")

            profile = self.get_profile(jwt)
            if not profile:
                print(Colors.error("  ❌ raiso jipuk profile, skip"))
                print()
                continue

            has_twitter = profile.get("socials", {}).get("twitter", None)
            if has_twitter:
                print(Colors.success("  ✅ twitter mu wes ke-register cok, Twitter/X"))
                print()
                continue

            twitter_cred = credentials[(idx - 1) % len(credentials)]
            tw_email = twitter_cred['email']
            tw_password = twitter_cred['password']

            print(Colors.info(f"  🐦 Twitter/X Account: {tw_email}"))

            success = False
            for attempt in range(1, MAX_TWITTER_LINK_RETRY + 1):
                print(Colors.info(f"  🔄 Linking attempt {attempt}/{MAX_TWITTER_LINK_RETRY}..."))
                success = self.link_twitter(jwt, tw_email, tw_password)

                if success:
                    print(Colors.success("  ✅ nah, Twitter/X nge-link sukses ki"))
                    break
                else:
                    print(Colors.warning("  ⚠️ ngelink e failed bajingan, cobo neh..."))
                    time.sleep(3)

            if not success:
                print(Colors.error("  ❌ raiso link Twitter/X dinggo akun iki"))

            wait = random.randint(5, 10)
            print(Colors.info(f"  ⏳ WTunggu sek bajingan {wait} sakdurung e next akun..."))
            time.sleep(wait)

        print(f"\n  {Colors.bold('='*50)}")
        print(Colors.bold("  ✅ Jos nge-link Twitter/X dinggo kabeh akun"))
        print(f"  {Colors.bold('='*50)}")

    def connect_discord_flow(self):
        print(f"\n{Colors.info('  📂 Loading akun sek...')}")
        accounts = self.load_accounts()

        if not accounts:
            print(Colors.error("  ❌ akun ra ketemu su!"))
            print(Colors.info("  💡 Create account ndisik nggo option [1]."))
            return

        print(Colors.success(f"  ✓ Found {len(accounts)} accounts\n"))

        credentials = self.load_discord_credentials()
        if not credentials:
            print(Colors.error("  ❌ raono discord credentials neng discord_credentials.txt"))
            print(Colors.info("  💡 tulung gawe file discord_credentials.txt nganggo format:"))
            print(Colors.info("     email,password"))
            return

        for idx, account in enumerate(accounts, 1):
            print(f"  {Colors.bold('='*50)}")
            print(Colors.bold(f"  Account {idx}/{len(accounts)}"))
            print(f"  {Colors.bold('='*50)}")

            email = account.get("email")
            wallet_address = account.get("wallet_address")

            print(Colors.info(f"  📧 B402 Email : {email}"))
            print(Colors.info(f"  💼 Wallet     : {wallet_address}"))

            account = self.check_and_refresh_token(account, idx - 1)
            if not account:
                print(Colors.error("  ❌ Skip akun iki, rajelas (cannot refresh token)"))
                print()
                continue

            jwt = account.get("jwt")

            profile = self.get_profile(jwt)
            if not profile:
                print(Colors.error("  ❌ raiso njipuk profile, skip!"))
                print()
                continue

            has_discord = profile.get("socials", {}).get("discord", None)
            if has_discord:
                print(Colors.success("  ✅ wes connect ning Discord"))
                print()
                continue

            disc_cred = credentials[(idx - 1) % len(credentials)]
            disc_email = disc_cred['email']
            disc_password = disc_cred['password']

            print(Colors.info(f"  💬 Discord Account: {disc_email}"))

            success = False
            for attempt in range(1, MAX_DISCORD_LINK_RETRY + 1):
                print(Colors.info(f"  🔄 Linking attempt {attempt}/{MAX_DISCORD_LINK_RETRY}..."))
                success = self.link_discord(jwt, disc_email, disc_password)

                if success:
                    print(Colors.success("  ✅ Discord sukses tersambung"))
                    break
                else:
                    print(Colors.warning("  ⚠️ ngelink e failed gan, nyobo meneh..."))
                    time.sleep(3)

            if not success:
                print(Colors.error("  ❌ Failed to link Discord for this account"))

            wait = random.randint(5, 10)
            print(Colors.info(f"  ⏳ Tunggu sek bajingan {wait} sakdurung e next akun..."))
            time.sleep(wait)

        print(f"\n  {Colors.bold('='*50)}")
        print(Colors.bold("  ✅ Done ngelink discord nggo kabeh akun"))
        print(f"  {Colors.bold('='*50)}")

    def load_twitter_credentials(self):
        if not os.path.exists(TWITTER_CREDENTIALS_FILE):
            return []

        credentials = []
        try:
            with open(TWITTER_CREDENTIALS_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(",")
                    if len(parts) >= 2:
                        credentials.append({
                            "email": parts[0].strip(),
                            "password": parts[1].strip()
                        })
            return credentials
        except Exception as e:
            print(Colors.error(f"  ❌ Gagal sambungke twitter_credentials.txt: {str(e)}"))
            return []

    def load_discord_credentials(self):
        if not os.path.exists(DISCORD_CREDENTIALS_FILE):
            return []

        credentials = []
        try:
            with open(DISCORD_CREDENTIALS_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(",")
                    if len(parts) >= 2:
                        credentials.append({
                            "email": parts[0].strip(),
                            "password": parts[1].strip()
                        })
            return credentials
        except Exception as e:
            print(Colors.error(f"  ❌ Gagal muat discord_credentials.txt: {str(e)}"))
            return []

    def get_profile(self, jwt):
        url = f"{BASE_URL}/api/api/v1/profile"
        headers = self._generate_headers(with_auth=True, jwt=jwt)

        try:
            response = self.session.get(url, headers=headers)
            data = response.json()

            if response.status_code == 200:
                return data.get("data", {})
            else:
                print(Colors.error(f"  ❌ Gagal njupuk profile: {data}"))
                return None
        except Exception as e:
            print(Colors.error(f"  ❌ Error get_profile: {str(e)}"))
            return None

    def link_twitter(self, jwt, twitter_email, twitter_password):
        try:
            print(Colors.info("  🌐 lagi nyiapake Playwright nggo login Twitter/X..."))

            async def flow():
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context(user_agent=self.fingerprint['user_agent'])
                    page = await context.new_page()

                    auth_url = (
                        f"https://twitter.com/i/oauth2/authorize?"
                        f"response_type={TWITTER_RESPONSE_TYPE}&"
                        f"client_id={TWITTER_CLIENT_ID}&"
                        f"redirect_uri={TWITTER_REDIRECT_URI}&"
                        f"scope={TWITTER_SCOPE}&"
                        f"state={generate_random_string(16)}&"
                        f"code_challenge={generate_random_string(43)}&"
                        f"code_challenge_method=plain"
                    )

                    await page.goto(auth_url)
                    await page.wait_for_timeout(3000)

                    try:
                        await page.fill('input[name="text"]', twitter_email)
                        await page.click('div[role="button"][data-testid="LoginForm_Login_Button"]')
                    except:
                        try:
                            await page.fill('input[autocomplete="username"]', twitter_email)
                            await page.click('div[role="button"]')
                        except Exception as e:
                            print(Colors.error(f"  ❌ Gagal nemok e field email Twitter: {str(e)}"))
                            await browser.close()
                            return False

                    await page.wait_for_timeout(3000)

                    try:
                        await page.fill('input[name="password"]', twitter_password)
                        await page.click('div[role="button"][data-testid="LoginForm_Login_Button"]')
                    except Exception as e:
                        print(Colors.error(f"  ❌ Gagal nemok e field password Twitter: {str(e)}"))
                        await browser.close()
                        return False

                    await page.wait_for_timeout(5000)

                    try:
                        await page.click('div[role="button"][data-testid="LoginForm_Login_Button"]')
                    except:
                        pass

                    await page.wait_for_timeout(5000)

                    final_url = page.url
                    if "code=" not in final_url:
                        print(Colors.error("  ❌ Ora entuk authorization code seko Twitter/X"))
                        await browser.close()
                        return False

                    parsed_url = urlparse(final_url)
                    query_params = parse_qs(parsed_url.query)
                    code = query_params.get("code", [None])[0]

                    await browser.close()

                    if not code:
                        print(Colors.error("  ❌ Authorization codene kosong"))
                        return False

                    print(Colors.success("  ✅ Entuk authorization code seko Twitter/X"))

                    headers = self._generate_headers(with_auth=True, jwt=jwt)
                    url = f"{BASE_URL}/api/api/v1/channel/twitter/callback"
                    payload = {
                        "code": code,
                        "state": "",
                        "redirectUri": TWITTER_REDIRECT_URI
                    }

                    resp = self.session.post(url, headers=headers, json=payload)
                    data = resp.json()

                    if resp.status_code == 200:
                        print(Colors.success("  ✅ B402 sukses nyambung karo Twitter/X"))
                        return True
                    else:
                        print(Colors.error(f"  ❌ B402 gagal nyambung karo Twitter/X, kontol: {data}"))
                        return False

            return asyncio.run(flow())

        except Exception as e:
            print(Colors.error(f"  ❌ Error link_twitter: {str(e)}"))
            return False

    def link_discord(self, jwt, discord_email, discord_password):
        try:
            print(Colors.info("  🌐 lagi nyiapake Playwright nggo login Discord..."))

            async def flow():
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=True)
                    context = await browser.new_context(user_agent=self.fingerprint['user_agent'])
                    page = await context.new_page()

                    oauth_url = (
                        f"https://discord.com/api/oauth2/authorize?"
                        f"client_id={DISCORD_CLIENT_ID}&"
                        f"redirect_uri={DISCORD_REDIRECT_URI}&"
                        f"response_type={DISCORD_RESPONSE_TYPE}&"
                        f"scope={DISCORD_SCOPE}"
                    )

                    await page.goto(oauth_url)
                    await page.wait_for_timeout(3000)

                    try:
                        await page.fill('input[name="email"]', discord_email)
                        await page.fill('input[name="password"]', discord_password)
                        await page.click('button[type="submit"]')
                    except Exception as e:
                        print(Colors.error(f"  ❌ Gagal nemoke field login Discord: {str(e)}"))
                        await browser.close()
                        return False

                    await page.wait_for_timeout(5000)

                    try:
                        await page.click('button[type="submit"]')
                        await page.wait_for_timeout(5000)
                    except:
                        pass

                    final_url = page.url
                    if "code=" not in final_url:
                        print(Colors.error("  ❌ Ora entuk authorization code seko Discord"))
                        await browser.close()
                        return False

                    parsed_url = urlparse(final_url)
                    query_params = parse_qs(parsed_url.query)
                    code = query_params.get("code", [None])[0]

                    await browser.close()

                    if not code:
                        print(Colors.error("  ❌ Authorization code kosong"))
                        return False

                    print(Colors.success("  ✅ Entuk authorization code seko Discord"))

                    headers = self._generate_headers(with_auth=True, jwt=jwt)
                    url = f"{BASE_URL}/api/api/v1/channel/discord/callback"
                    payload = {
                        "code": code,
                        "state": "",
                        "redirectUri": DISCORD_REDIRECT_URI
                    }

                    resp = self.session.post(url, headers=headers, json=payload)
                    data = resp.json()

                    if resp.status_code == 200:
                        print(Colors.success("  ✅ B402 sukses nyambung karo Discord"))
                        return True
                    else:
                        print(Colors.error(f"  ❌ B402 gagal nyambung karo Discord, Blok!: {data}"))
                        return False

            return asyncio.run(flow())

        except Exception as e:
            print(Colors.error(f"  ❌ Error link_discord: {str(e)}"))
            return False

    def import_and_login_flow(self):
        if not self.private_keys:
            print(Colors.error(f"  ❌ File {PRIVATE_KEYS_FILE} ora iso nemu nek ora yo kosong"))
            print(Colors.info(f"  💡 Gawe file {PRIVATE_KEYS_FILE} trus isi karo private key (tiap baris siji)"))
            return

        existing_accounts = self.load_accounts()
        mapped_wallets = {acc["wallet_address"].lower(): acc for acc in existing_accounts if "wallet_address" in acc}

        for idx, pk in enumerate(self.private_keys, 1):
            print(f"\n{Colors.bold('='*50)}")
            print(Colors.bold(f"  [{idx}/{len(self.private_keys)}] Login nganggo Private Key"))
            print(f"{Colors.bold('='*50)}")

            try:
                account = Account.from_key(pk)
                wallet_address = account.address
            except Exception as e:
                print(Colors.error(f"  ❌ Private key ora valid babi: {str(e)}"))
                continue

            print(Colors.info(f"  💼 Wallet: {wallet_address}"))

            existing = mapped_wallets.get(wallet_address.lower())
            if existing:
                print(Colors.info("  ℹ️ Wallet iki wis ana ing accounts.json bajingan, nyoba refresh token, goblok tenan..."))
                refreshed = self.check_and_refresh_token(existing, existing_accounts.index(existing))
                if refreshed:
                    print(Colors.success("  ✅ Token wis di-refresh nggo wallet iki"))
                else:
                    print(Colors.error("  ❌ Gagal refresh token nggo wallet iki"))
                continue

            turnstile_token = self.get_turnstile_token(wallet_address)
            if not turnstile_token:
                continue

            lid = str(uuid.uuid4())
            client_id = self.fingerprint['device_id']

            challenge = self.get_challenge(wallet_address, turnstile_token, lid, client_id)
            if not challenge:
                continue

            signature = sign_message(pk, challenge)

            jwt_web3 = self.complete_challenge(wallet_address, signature, lid, client_id)
            if not jwt_web3:
                continue

            nonce = self.get_wallet_nonce(wallet_address, jwt_web3)
            if nonce is None:
                continue

            connect_signature = sign_message(pk, nonce)

            connected = self.connect_wallet(jwt_web3, wallet_address, connect_signature, nonce)
            if not connected:
                continue

            email = f"imported_{wallet_address.lower()}@b402.local"
            password = generate_password(12)

            new_account = {
                "email": email,
                "password": password,
                "wallet_address": wallet_address,
                "private_key": pk,
                "jwt": jwt_web3,
                "fingerprint": self.fingerprint,
                "created_at": time.time(),
                "imported": True
            }

            existing_accounts.append(new_account)
            self.save_accounts(existing_accounts)

            print(Colors.success("  ✅ Wallet iki wis diimpor lan disimpen nang accounts.json"))

        print(f"\n{Colors.bold('='*50)}")
        print(Colors.bold("  ✅ Rampung proses impor & login kabeh private key"))
        print(f"{Colors.bold('='*50)}")


def print_main_menu():
    print(f"\n{Colors.bold('='*50)}")
    print(Colors.bold("  B402.AI PIRANTI (TOOLS)"))
    print(f"{Colors.bold('='*50)}")
    print(f"\n{Colors.info('  [1] Gawe Akun Otomatis (Auto Create Account)')}")
    print(Colors.info("  [2] lagi ndelok Status & Progres"))
    print(Colors.info("  [3] Nyambungake X (Twitter)"))
    print(Colors.info("  [4] Nyambungake Discord"))
    print(Colors.warning("  [5] 🔑 Impor & Login nggo Private Key"))
    print(Colors.info("  [6] 🔁 Spam Mint (endpoint custom)"))
    print(Colors.error("  [0] Metu / Tutup Program"))
    print(f"\n{Colors.bold('='*50)}")


def main():
    while True:
        print_main_menu()
        choice = input(f"\n{Colors.info('  Milih menu: ')}").strip()

        if choice == "1":
            print(f"\n{Colors.bold('='*50)}")
            print(Colors.bold("  AUTO GAWE AKUN SEK (CREATE ACCOUNT)"))
            print(f"{Colors.bold('='*50)}\n")

            try:
                num_accounts = int(
                    input(
                        Colors.info("  Pinten akun sing arep digawe mbut? ")
                    )
                )
                print()

                success = 0
                failed = 0

                for i in range(num_accounts):
                    print(
                        Colors.bold(
                            f"\n[{i+1}/{num_accounts}] Gawe akun anyar sek gan..."
                        )
                    )
                    tools = B402Tools()
                    result = tools.create_account_flow()

                    if result:
                        success += 1
                    else:
                        failed += 1
                        print(Colors.error("  ❌ Gagal gawe akun iki, babi!"))

                    # ora ana jeda antar akun, langsung lanjut

                print(f"\n{Colors.bold('='*50)}")
                print(Colors.bold("  RINGKESAN GAWE AKUN"))
                print(f"{Colors.bold('='*50)}")
                print(Colors.info(f"  Total akun sek di cobo: {num_accounts}"))
                print(Colors.success(f"  ✅ Sukses : {success}"))
                print(Colors.error(f"  ❌ Gagal  : {failed}"))
                print(f"{Colors.bold('='*50)}")

                input(
                    Colors.info(
                        "\n  Pencet Enter nggo bali neng menu utama, ora Pencet penthil..."
                    )
                )

            except ValueError:
                print(Colors.error("  ❌ Leboken kudu angka, ora drijimu lebok e gawok!"))
                time.sleep(2)
            except KeyboardInterrupt:
                print(Colors.warning("\n\n  ⚠️  tak stop gan! (Ctrl+C)"))
                time.sleep(2)

        elif choice == "2":
            print(f"\n{Colors.bold('='*50)}")
            print(Colors.bold("  LAGI MRIKSO STATUS & PROGRES"))
            print(f"{Colors.bold('='*50)}")

            tools = B402Tools()
            tools.check_status_and_progress()

            input(
                Colors.info(
                    "\n  Pencet Enter nggo bali neng menu utama, ora Pencet penthil..."
                )
            )

        elif choice == "3":
            print(f"\n{Colors.bold('='*50)}")
            print(Colors.bold("  lagi nyambung twitter su, X (TWITTER)"))
            print(f"{Colors.bold('='*50)}")

            tools = B402Tools()
            tools.connect_twitter_flow()

            input(
                Colors.info(
                    "\n  Pencet Enter nggo bali neng menu utama, ora Pencet penthil..."
                )
            )

        elif choice == "4":
            print(f"\n{Colors.bold('='*50)}")
            print(Colors.bold("  NYAMBUNGAKÉ DISCORD"))
            print(f"{Colors.bold('='*50)}")

            tools = B402Tools()
            tools.connect_discord_flow()

            input(
                Colors.info(
                    "\n  Pencet Enter nggo bali neng menu utama, ora Pencet penthil..."
                )
            )

        elif choice == "5":
            print(f"\n{Colors.bold('='*50)}")
            print(Colors.bold("  🔑 IMPOR & LOGIN NGANGGO PRIVATE KEY"))
            print(f"{Colors.bold('='*50)}")
            print(Colors.info("\n  📝 Syarat:"))
            print(
                Colors.info(
                    "     - Wallet wis tau kedaftar ing B402 (wis ke register cok!)"
                )
            )
            print(Colors.info("     - ra butuh email maneh"))
            print(
                Colors.info(
                    "     - Format: siji private key per baris ning file privkey.txt\n"
                )
            )

            confirm = input(
                Colors.warning("  lanjut ora? (y/n): ")
            ).strip().lower()
            if confirm != "y":
                continue

            tools = B402Tools()
            tools.import_and_login_flow()

            input(
                Colors.info(
                    "\n  Pencet Enter nggo bali neng menu utama, ora Pencet penthil..."
                )
            )

        elif choice == "6":
            print(f"\n{Colors.bold('='*50)}")
            print(Colors.bold("  🔁 SPAM MINT (ENDPOINT CUSTOM)"))
            print(f"{Colors.bold('='*50)}")

            tools = B402Tools()
            tools.spam_mint_box_flow()

            input(
                Colors.info(
                    "\n  Pencet Enter nggo bali neng menu utama, ora Pencet penthil..."
                )
            )

        elif choice == "0":
            print(Colors.success("\n  👋 Suwun gan, Program tak tutup yo.\n"))
            break

        else:
            print(Colors.error("\n  ❌ Menu raiso dikenali cok!"))
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Colors.warning("\n\n  ⚠️  Program stopped by user\n"))
    except Exception as e:
        print(Colors.error(f"\n  ❌ Error: {str(e)}\n"))
        traceback.print_exc()
