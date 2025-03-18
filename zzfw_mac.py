from flask import Flask, request, jsonify
import requests
from gmssl import sm4
import base64
import re
import json
import urllib3
from datetime import datetime

# 获取当前系统时间
now = datetime.now()
current_time = now.strftime("%Y-%m-%d %H:%M:%S")

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


def validate_hex_key(key: str) -> bool:
    """验证32位十六进制密钥格式"""
    return re.fullmatch(r'^[a-fA-F0-9]{32}$', key) is not None


def sm4_ecb_encrypt(key_hex: str, data: dict) -> str:
    """整合加密流程：序列化->填充->加密->Base64编码"""
    try:
        # 密钥处理
        key = bytes.fromhex(key_hex)

        # JSON序列化（紧凑格式）
        json_str = json.dumps(data, separators=(',', ':'))
        plain_bytes = json_str.encode('utf-8')

        # SM4加密
        cipher = sm4.CryptSM4()
        cipher.set_key(key, sm4.SM4_ENCRYPT)
        ciphertext = cipher.crypt_ecb(plain_bytes)

        # Base64编码
        plain_bytes_jm = base64.b64encode(ciphertext).decode('utf-8')
        print(f'{current_time} 加密后请求报文：',plain_bytes_jm)
        return base64.b64encode(ciphertext).decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"加密失败: {str(e)}")


def sm4_ecb_decrypt(key_hex: str, ciphertext_b64: str) -> str:
    """解密流程：Base64解码->解密->去除填充->转换字符串"""
    try:
        if not validate_hex_key(key_hex):
            raise ValueError("无效的密钥格式")
        key = bytes.fromhex(key_hex)

        ciphertext = base64.b64decode(ciphertext_b64)

        cipher = sm4.CryptSM4()
        cipher.set_key(key, sm4.SM4_DECRYPT)
        plain_bytes_padded = cipher.crypt_ecb(ciphertext)
        plain_bytes = plain_bytes_padded

        return plain_bytes.decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"解密失败: {str(e)}")


@app.route('/', methods=['POST'])
def handle_request():
    """统一请求处理入口"""
    try:
        # 1. 基础校验
        required_headers = ['my', 'jrdwptbh', 'sydwptbh', 'fwbm', 'nlbm', 'ylbm', 'mbdz']
        missing = [h for h in required_headers if h not in request.headers]
        if missing:
            return jsonify({"error": f"缺少必要请求头: {', '.join(missing)}"}), 400

        # 2. 密钥验证
        key_hex = request.headers['my']
        if not validate_hex_key(key_hex):
            return jsonify({"error": "无效的32位十六进制密钥"}), 400

        # 3. 数据解析
        try:
            payload = request.get_json()
            print(f'{current_time} 未加密请求报文:',payload)

            if not isinstance(payload, dict):
                raise ValueError()
        except:
            return jsonify({"error": "请求体必须是合法JSON对象"}), 400

        # 4. 数据加密
        try:
            encrypted = sm4_ecb_encrypt(key_hex, payload)
        except RuntimeError as e:
            return jsonify({"error": str(e)}), 500

        # 5. 请求转发
        headers_ys = request.headers
        print(f'{current_time} 原始请求头：',headers_ys)
        target_url = request.headers['mbdz']
        print(f'{current_time} 转发地址：',target_url)
        filtered_headers = {
            k.lower(): v
            for k, v in request.headers.items()
            if k.lower() not in ["mbdz", "host"]
        }
        print(f'{current_time} 转发请求头：',filtered_headers)
        response = requests.post(
            target_url,
            data=encrypted,
            headers=filtered_headers,
            verify=False # 关闭SSL验证
        )

        # 解析响应JSON
        response_data = response.json()
        print(f'{current_time} 原始返回：',response_data)

        # 提取并解密Data字段

        data_encrypted_body = response_data.get('body', {})
        data_encrypted_Response = json.loads(data_encrypted_body).get('Response', {})
        data_encrypted = data_encrypted_Response.get('Data', {})

        if not data_encrypted:
            return jsonify({'error': '响应中缺少Data字段'}), 500

        decrypted_data = sm4_ecb_decrypt(key_hex, data_encrypted)

        # 替换解密后的Data
        data_encrypted_Response['Data'] = decrypted_data
        data_encrypted_body = json.loads(data_encrypted_body)
        data_encrypted_body['Response'] = data_encrypted_Response
        response_data['body'] = data_encrypted_body


        # 返回修改后的响应
        return jsonify(response_data)
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'请求失败: {str(e)}'}), 500
    except RuntimeError as e:
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': f'服务器错误: {str(e)}'}), 500


if __name__ == '__main__':
    app.run(host='localhost', port=8080, debug=False)