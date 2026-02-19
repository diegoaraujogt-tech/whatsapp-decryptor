from flask import Flask, request, jsonify, Response
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
    return 'WhatsApp Decryptor OK - v5.0 (Decrypt Only)'


@app.route('/decrypt-and-return', methods=['POST'])
def decrypt_and_return():
    """Decripta e retorna o arquivo em base64 para o N8N fazer upload"""
    try:
        data = request.json
        file_url = data.get('url', '')
        media_key_b64 = data.get('mediaKey', '')
        media_type = data.get('mediaType', 'video')

        print(f"=== DECRYPT-AND-RETURN v5.0 ===", file=sys.stderr)
        print(f"URL: {file_url[:80]}...", file=sys.stderr)
        print(f"MediaType: {media_type}", file=sys.stderr)
        print(f"MediaKey length: {len(media_key_b64)} chars", file=sys.stderr)

        if not file_url:
            return jsonify({'error': 'url is required'}), 400
        if not media_key_b64:
            return jsonify({'error': 'mediaKey is required'}), 400

        # Decode mediaKey with padding fix
        try:
            missing_padding = 4 - len(media_key_b64) % 4
            if missing_padding != 4:
                media_key_b64 = media_key_b64 + '=' * missing_padding
            media_key_bytes = base64.b64decode(media_key_b64)
        except Exception as e:
            return jsonify({
                'error': f'mediaKey decode failed: {str(e)}',
                'mediaKey_received': media_key_b64,
                'mediaKey_length': len(media_key_b64)
            }), 400

        if len(media_key_bytes) != 32:
            return jsonify({'error': f'Invalid media key: {len(media_key_bytes)} bytes (expected 32)'}), 400

        # Step 1: Download
        print(f"Step 1: Downloading...", file=sys.stderr)
        resp = requests.get(file_url, timeout=300)
        resp.raise_for_status()
        encrypted_data = resp.content
        print(f"Downloaded {len(encrypted_data)} bytes", file=sys.stderr)

        if len(encrypted_data) < 100:
            return jsonify({
                'error': f'File too small ({len(encrypted_data)} bytes) - URL may have expired',
                'response_preview': encrypted_data[:200].decode('utf-8', errors='replace')
            }), 400

        # Step 2: Decrypt
        print(f"Step 2: Decrypting...", file=sys.stderr)
        decrypted = decrypt_media(encrypted_data, media_key_bytes, media_type)
        print(f"Decrypted {len(decrypted)} bytes", file=sys.stderr)
        del encrypted_data

        # Step 3: Return base64
        decrypted_b64 = base64.b64encode(decrypted).decode('utf-8')
        del decrypted
        print(f"Returning {len(decrypted_b64)} base64 chars", file=sys.stderr)

        return jsonify({
            'success': True,
            'decryptedData': decrypted_b64,
            'size': len(decrypted_b64)
        })

    except requests.exceptions.RequestException as e:
        print(f"DOWNLOAD ERROR: {str(e)}", file=sys.stderr)
        return jsonify({'error': f'Download failed: {str(e)}'}), 500
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500


# Mantém a rota antiga caso queira usar depois
@app.route('/decrypt-and-upload', methods=['POST'])
def decrypt_and_upload():
    return jsonify({'error': 'Route disabled. Use /decrypt-and-return instead.'}), 400


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
