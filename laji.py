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


async def get_country_by_ip(ip_address, proxy):
    url = f'http://ip-api.com/json/{ip_address}'
    try:
        async with ClientSession() as session:
            async with session.get(url, proxy=proxy) as response:
                result = await response.json()
                return result.get("country")
    except Exception as e:
        print(f"Error fetching country for IP {ip_address}: {e}")
        return None


async def extract_ip_from_result(result: str) -> str:
    match = re.search(r'@([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):', result)
    if match:
        return match.group(1)
    else:
        return None


async def generate_nonce():
    return ''.join([str(random.randint(0, 9)) for _ in range(9)])


async def generate_hmac_sha1_signature(key: str, message: str) -> str:
    key_bytes = bytes(key, 'utf-8')
    message_bytes = bytes(message, 'utf-8')
    sha1_hmac = hmac.new(key_bytes, message_bytes, hashlib.sha1).digest()
    return base64.b64encode(sha1_hmac).decode('utf-8')


async def decrypt_aes_cbc(key: str, iv: bytes, encrypted_data: str) -> str:
    encrypted_data = base64.b64decode(encrypted_data)
    cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode('utf-8', errors='ignore')


async def post_request(url: str, headers: dict, data: str, proxy) -> dict:
    try:
        async with ClientSession() as session:
            async with session.post(url=url, headers=headers, data=data, timeout=2, proxy=proxy) as response:
                response_data = await response.text()
                return json.loads(response_data).get('data', [])
    except Exception as e:
        print(f"Error during post request: {e}")
        return []


async def process_shadowsocks_data(data: list, key: str, iv: bytes) -> str:
    result = []
    for encrypted_data in data:
        decrypted_data = await decrypt_aes_cbc(key, iv, encrypted_data)
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


async def fetch_and_process_data(proxy):
    nonce = await generate_nonce()
    time_0 = str(int(time.time()))
    message = f"h/hfX}}$ZDHcWH5rLpFdn=:x5D%Nh-gPOST/v3/choose_server/?nonce={nonce}&sid=h/hfX}}$ZDHcWH5rLpFdn=:x5D%Nh-g&ts={time_0}&version=40"
    key = "G]n(/E5WdRz]:=:aq$46BA-$qjj3gZ"
    sign = await generate_hmac_sha1_signature(key, message)
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
    response_data = await post_request(url, headers, data, proxy)
    if response_data:
        key = 'k6NASqTxLWJ4cXF9kGRfl5Ltmiy0qGU1'
        iv = base64.b64decode('Ztacps4Jd4f+Ms6pWiJcbA==')
        return await process_shadowsocks_data(response_data, key, iv)
    return ""


async def main_fly(proxy):
    total_result = ""
    consecutive_count = 0
    while True:
        result = await fetch_and_process_data(proxy)
        if result:
            tasks = []
            for i in result:
                if i not in total_result:
                    ip_address = await extract_ip_from_result(i)
                    task = asyncio.create_task(get_country_by_ip(ip_address, proxy))
                    tasks.append((task, i))  # Collect task and data
                else:
                    consecutive_count += 1

            if tasks:
                # Run all tasks concurrently
                countries = await asyncio.gather(*[task for task, _ in tasks])
                for country, (task, i) in zip(countries, tasks):
                    if country:
                        #print(f"IP 地址 {ip_address} 所在的国家是：{country}")
                        total_result += f"{i}#{country}\n"
                    else:
                        print(f"Error fetching country for {i}")
                    list_len = len(total_result.split('\n')) - 1
                    print(total_result, f"当前抓取到{list_len}个节点。")
                    pyperclip.copy(total_result)

            if consecutive_count >= 10:
                print("连续10次抓到重复节点，停止循环，已复制到剪切板。")
                break
        await asyncio.sleep(1)  # Reduce delay for faster execution


async def main(proxy):
    total_result = ""
    consecutive_count = 0
    while True:
        result = await fetch_and_process_data(proxy)
        if result:
            for i in result:
                if i not in total_result:
                    total_result += f"{i}\n"
                    consecutive_count = 0
                    list_len = len(total_result.split('\n')) - 1
                    print(total_result, f"当前抓取到{list_len}个节点。")
                else:
                    consecutive_count += 1
            if consecutive_count >= 10:
                print("连续10次抓到重复节点，停止循环。")
                break


def choose_method(proxy):
    method = input('请选择抓取模式：\n1.进入快速抓取模式\n2.给节点标注地区(时间较长)\n')
    if method == "1":
        asyncio.run(main(proxies))
    elif method == "2":
        asyncio.run(main_fly(proxies))
    else:
        print("方法不存在，请重新选择 1/2")
        return choose_method(proxy)


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
    proxy_input = input('常用默认代理端口：\nclash：7890\nv2rayN:10809\n小火箭：1082\n请输入本地代理端口：')
    if proxy_input:
        proxies = f"http://127.0.0.1:{proxy_input}"
    else:
        proxies = None
    start = choose_method(proxies)

