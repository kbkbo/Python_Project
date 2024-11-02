import requests
import json
import base64
import pyaes
import re

a = "c3e7254f65b8c39e9d6391fd422140f3"
b = "3690911436885991424"
Fuckme = []

def c(d, e, f):
    d = base64.b64decode(d)
    aes = pyaes.AESModeOfOperationCBC(e, iv=f)
    decrypted = b""
    while d:
        decrypted += aes.decrypt(d[:16])
        d = d[16:]
    padding_len = decrypted[-1]
    return decrypted[:-padding_len].decode('utf-8')

def i():
    j = "https://api.9527.click/v2/node/list"
    k = {
        'Host': 'api.9527.click',
        'Content-Type': 'application/json',
        'Connection': 'keep-alive',
        'Accept': '*/*',
        'User-Agent': 'International/3.3.35 (iPhone; iOS 18.0.1; Scale/3.00)',
        'Accept-Language': 'zh-Hans-CN;q=1',
        'Accept-Encoding': 'gzip, deflate, br'
    }
    l = {
        "key": "G8Jxb2YtcONGmQwN7b5odg==",
        "uid": b,
        "vercode": "1",
        "uuid": "0273F74A-3F2E-44FB-8F87-717C9E3518E3"
    }
    m = requests.post(j, headers=k, json=l)
    if m.status_code == 200:
        return json.loads(m.text)
    else:
        print(f"fw: {m.status_code}")
        return None

def n():
    o = b'VXH2THdPBsHEp+TY'
    p = b'VXH2THdPBsHEp+TY'
    q = i()
    if not q:
        print("dashabi")
        return
    if 'data' not in q:
        print("dashabi")
        return
    for r in q['data']:
        if 'ip' in r and r['ip']:
            r['ip'] = c(r['ip'], o, p)
        if 'host' in r and r['host']:
            r['host'] = c(r['host'], o, p)
        if 'ov_host' in r and r['ov_host']:
            r['ov_host'] = c(r['ov_host'], o, p)
        s = r.get('host') or r.get('ip')
        t = r.get('name', 'sb')
        u = f"trojan://{b}@{s}:443?allowInsecure=1#{t}"
        Fuckme.append(u)

    Fuckme.sort(key=lambda link: re.search(r'#(\w+)', link).group(1) if re.search(r'#(\w+)', link) else '')
    encoded_content = base64.b64encode('\n'.join(Fuckme).encode('utf-8')).decode('utf-8')
    post_to_dpaste(encoded_content)

def post_to_dpaste(encoded_content):
    response = requests.post("https://dpaste.com/api/", data={"content": encoded_content})
    if response.status_code == 201:
        dpaste_url = response.text.strip() + ".conf"
        print("获取订阅中…")
        print("链接:", dpaste_url)
    else:
        print("发布到 dpaste 失败，状态码:", response.status_code)

if __name__ == "__main__":
    n()
