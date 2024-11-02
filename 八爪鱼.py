import requests
import random
import string
import warnings
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

def uuid_a():
    characters = string.ascii_lowercase + string.digits
    random_string = ''.join(random.choice(characters) for i in range(8))
    return random_string

email_prefix = uuid_a()
email = f"{email_prefix}@163.com"

class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        kwargs['ssl_context'] = context
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)

session = requests.Session()
session.mount("https://", TLSAdapter())

headers = {
    'User-Agent': 'Octopus_Android',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded'
}

url_register = "https://www.otcopusapp.cc/lx3af288h5i8pz380/api/v1/passport/auth/register"
params_register = {
    'email': email,
    'password': '123123123',
    'invite_code': 'e0duFfft',
    'email_code': ''
}

warnings.filterwarnings("ignore", message="Unverified HTTPS request is being made.*")

try:
    response_register = session.post(url_register, headers=headers, data=params_register, verify=False)
    response_register.raise_for_status()
    token = response_register.json().get("data", {}).get("token")
    print(f"注册成功，用户token: {token}")
except requests.exceptions.RequestException as e:
    print(f"注册请求失败: {e}")
    token = None

if token:
    url_login = "https://www.otcopusapp.cc/lx3af288h5i8pz380/api/v1/passport/auth/login"
    params_login = {
        'email': email,
        'password': '123123123'
    }

    try:
        response_login = session.post(url_login, headers=headers, data=params_login, verify=False)
        response_login.raise_for_status()
        login_data = response_login.json().get("data", {})
        login_token = login_data.get("token")
        print(f"登录成功，登录token: {login_token}")

        subscribe_url = f"https://www.otcopusapp.cc/lx3af288h5i8pz380/api/v1/client/subscribe?token={login_token}"
        print(f"订阅URL: {subscribe_url}")
        
    except requests.exceptions.RequestException as e:
        print(f"登录请求失败: {e}")
        login_token = None
else:
    print("无法继续登录或构造订阅URL，因为注册失败。")
