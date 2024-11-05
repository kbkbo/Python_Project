import hmac
import re
import hashlib
import random
import base64
import time
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import asyncio
from aiohttp import ClientSession
import pyperclip
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
def get_country_by_ip(ip_address):
    url = f'http://ip-api.com/json/{ip_address}'
    session = requests.Session()
    retry_strategy = Retry(
        total=5, 
        backoff_factor=1, 
        status_forcelist=[500, 502, 503, 504], 
        allowed_methods=["GET", "POST"] 
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)    
    try:
        response = session.get(url)
        return response.json().get("country")
    except requests.exceptions.RequestException as e:
        return None
def extract_ip_from_result(result: str) -> str:
    match = re.search(r'@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):', result)
    if match:
        return match.group(1)
    else:
        return None
def generate_nonce():
    return ''.join([str(random.randint(0, 9)) for _ in range(9)])
def generate_hmac_sha1_signature(key: str, message: str) -> str:
    key_bytes = bytes(key, 'utf-8')
    message_bytes = bytes(message, 'utf-8')
    sha1_hmac = hmac.new(key_bytes, message_bytes, hashlib.sha1).digest()
    return base64.b64encode(sha1_hmac).decode('utf-8')
def decrypt_aes_cbc(key: str, iv: bytes, encrypted_data: str) -> str:
    encrypted_data = base64.b64decode(encrypted_data)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode('utf-8', errors='ignore')
async def post_request(url: str, headers: dict, data: str) -> dict:
    try:
        async with ClientSession() as session:
            async with session.post(url=url, headers=headers, data=data, timeout=2) as response:
                response_data = await response.text()
                return json.loads(response_data).get('data', [])
    except Exception as e:
        return []
def process_shadowsocks_data(data: list, key: str, iv: bytes) -> str:
    result = []
    for encrypted_data in data:
        decrypted_data = decrypt_aes_cbc(key, iv, encrypted_data)
        try:
            sub_str = 'c3M6L' + decrypted_data.split('c3M6L')[1].split('\\')[0]
            decoded_data = base64.b64decode(sub_str).decode()
            server_info = decoded_data.split(':')[4].split('.')
            server_ip = f"{server_info[2]}.{server_info[8]}.{server_info[6]}.{server_info[10]}"
            server = f"ss://{base64.b64encode(('chacha20-ietf-poly1305:' + decoded_data.split(':')[5]).encode()).decode()}@{server_ip}:8313"
            if server not in result:
                result.append(server)
        except Exception as e:
            pass  
    return result
async def fetch_and_process_data():
    nonce = generate_nonce()
    time_0 = str(int(time.time()))
    message = f"h/hfX}}$ZDHcWH5rLpFdn=:x5D%Nh-gPOST/v3/choose_server/?nonce={nonce}&sid=h/hfX}}$ZDHcWH5rLpFdn=:x5D%Nh-g&ts={time_0}&version=40"
    key = "G]n(/E5WdRz]:=:aq$46BA-$qjj3gZ"
    sign = generate_hmac_sha1_signature(key, message)
    data = json.dumps({
        "version": 40,
        "nonce": nonce,
        "ts": time_0,
        "sid": "h/hfX}$ZDHcWH5rLpFdn=:x5D%Nh-g",
        "sign": sign
    })
    headers = {
        'Content-Type': 'application/json; charset=utf-8',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ONEPLUS A5000 Build/NZH54D)',
        'Host': 'api.smallwings.cc',
        'Connection': 'Keep-Alive',
        'Accept-Encoding': 'gzip',
        'Content-Length': str(len(data))
    }
    url = "http://api.smallwings.cc/api/v3/choose_server"
    response_data = await post_request(url, headers, data)
    if response_data:
        key = 'k6NASqTxLWJ4cXF9kGRfl5Ltmiy0qGU1'
        iv = base64.b64decode('Ztacps4Jd4f+Ms6pWiJcbA==')
        return process_shadowsocks_data(response_data, key, iv)
    return ""
async def main_fly():
    total_result = "" 
    consecutive_count = 0 
    while True:  
        result = await fetch_and_process_data()
        if result:
            for i in result:
                if i not in total_result:
                    ip_address = extract_ip_from_result(i)
                    country = get_country_by_ip(ip_address)
                    print(f"IP 地址 {ip_address} 所在的国家是：{country}")                            
                    total_result +=  f"{i}#{country}\n"   
                    list_len = len(total_result.split('\n'))-1             
                    print(total_result, f"当前抓取到{list_len}个节点。")        
                    pyperclip.copy(total_result) 
                else:
                    consecutive_count += 1  
            if consecutive_count >= 10:
                print("连续10次抓到重复节点，停止循环，已复制到剪切板。")
                break
        await asyncio.sleep(5)               
async def main():
    total_result = ""  
    consecutive_count = 0 
    while True: 
        result = await fetch_and_process_data()
        if result:
            for i in result:
                if i not in total_result:                            
                    total_result +=  f"{i}\n"  
                    consecutive_count = 0  
                    list_len = len(total_result.split('\n'))-1
                    print(total_result, f"当前抓取到{list_len}个节点。") 
                else:
                    consecutive_count += 1 
            if consecutive_count >= 10:
                print("连续10次抓到重复节点，停止循环。")
                break
        
    



if __name__ == "__main__":
    text = """
    ****************
    ****************
    此脚本仅用于学术交流，
    禁止非法使用，
    请在24小时内删除！
    ****************
    ****************
    """
    print(text)
    user_input = input('输入任意按键进入快速抓取模式\n\n输入 flynb 给节点标注地区(时间较长)\n')
    if user_input == "flynb":
        asyncio.run(main_fly())
    else:
        asyncio.run(main())
