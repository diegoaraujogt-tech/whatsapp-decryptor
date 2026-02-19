from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64
import hashlib
import hmac as hmac_module
import requests
import os
import sys

app = Flask(__name__)

APP_INFO = {
    "video": b"WhatsApp Video Keys",
    "image": b"WhatsApp Image Keys",
    "audio": b"WhatsApp Audio Keys",
    "document": b"WhatsApp Document Keys",
}


def hkdf_expand(key, length, app_info=b""):
    key = hmac_module.new(b"\0" * 32, key, hashlib.sha256).digest()
    key_stream = b""
    key_block = b""
    block_index = 1
    while len(key_stream) < length:
        key_block = hmac_module.new(
            key,
            msg=key_block + app_info + chr(block_index).encode("utf-8"),
            digestmod=hashlib.sha256
        ).digest()
        block_index += 1
        key_stream += key_block
    return key_stream[:length]


def aes_unpad(s):
    if len(s) == 0:
        return s
    pad_len = s[-1]
    if pad_len < 1 or pad_len > 16:
        return s
    if s[-pad_len:] != bytes([pad_len]) * pad_len:
        return s
    return s[:-pad_len]


def decrypt_media(encrypted_data, media_key_bytes, media_type="video"):
    info = APP_INFO.get(media_type, b"WhatsApp Video Keys")
    media_key_expanded = hkdf_expand(media_key_bytes, 112, info)
    iv = media_key_expanded[:16]
    cipher_key = media_key_expanded[16:48]
    file_data = encrypted_data[:-10]
    cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(file_data)
    decrypted = aes_unpad(decrypted)
    return decrypted


@app.route('/')
def home():
    return 'WhatsApp Decryptor OK - v3 (URL+base64)'


@app.route('/decrypt-url', methods=['POST'])
def decrypt_url():
    """Downloads .enc from WhatsApp URL, decrypts, returns base64 JSON"""
    try:
        data = request.json
        file_url = data.get('url', '')
        media_key_b64 = data.get('mediaKey', '')
        media_type = data.get('mediaType', 'video')

        print(f"=== DECRYPT-URL v3 ===", file=sys.stderr)
        print(f"URL: {file_url[:80]}...", file=sys.stderr)
        print(f"MediaType: {media_type}", file=sys.stderr)

        if not file_url:
            return jsonify({'error': 'URL is required'}), 400
        if not media_key_b64:
            return jsonify({'error': 'mediaKey is required'}), 400

        media_key_bytes = base64.b64decode(media_key_b64)
        if len(media_key_bytes) != 32:
            return jsonify({'error': f'Invalid media key length: {len(media_key_bytes)}'}), 400

        # Download encrypted file from WhatsApp CDN
        print(f"Downloading from WhatsApp CDN...", file=sys.stderr)
        resp = requests.get(file_url, timeout=300)
        resp.raise_for_status()

        encrypted_data = resp.content
        print(f"Downloaded {len(encrypted_data)} bytes", file=sys.stderr)

        if len(encrypted_data) < 11:
            return jsonify({'error': f'Downloaded file too small: {len(encrypted_data)} bytes'}), 400

        # Decrypt
        decrypted = decrypt_media(encrypted_data, media_key_bytes, media_type)
        print(f"Decrypted {len(decrypted)} bytes", file=sys.stderr)

        # Return base64 encoded
        decrypted_b64 = base64.b64encode(decrypted).decode('utf-8')
        print(f"Base64 length: {len(decrypted_b64)}", file=sys.stderr)

        return jsonify({
            'decryptedData': decrypted_b64,
            'size': len(decrypted)
        })

    except requests.exceptions.RequestException as e:
        print(f"DOWNLOAD ERROR: {str(e)}", file=sys.stderr)
        return jsonify({'error': f'Failed to download: {str(e)}'}), 500
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
