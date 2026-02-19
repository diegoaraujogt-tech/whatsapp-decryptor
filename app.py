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
    return 'WhatsApp Decryptor OK - v5.1 (Binary Response)'


@app.route('/decrypt-and-return', methods=['POST'])
def decrypt_and_return():
    try:
        data = request.json
        file_url = data.get('url', '')
        media_key_b64 = data.get('mediaKey', '')
        media_type = data.get('mediaType', 'video')
        mime_type = data.get('mimeType', 'video/mp4')

        print(f"=== DECRYPT-AND-RETURN v5.1 (binary) ===", file=sys.stderr)
        print(f"URL: {file_url[:80]}...", file=sys.stderr)
        print(f"MediaType: {media_type}", file=sys.stderr)

        if not file_url:
            return jsonify({'error': 'url is required'}), 400
        if not media_key_b64:
            return jsonify({'error': 'mediaKey is required'}), 400

        # Decode mediaKey
        try:
            missing_padding = 4 - len(media_key_b64) % 4
            if missing_padding != 4:
                media_key_b64 = media_key_b64 + '=' * missing_padding
            media_key_bytes = base64.b64decode(media_key_b64)
        except Exception as e:
            return jsonify({'error': f'mediaKey decode failed: {str(e)}'}), 400

        if len(media_key_bytes) != 32:
            return jsonify({'error': f'Invalid media key: {len(media_key_bytes)} bytes'}), 400

        # Download
        print(f"Downloading...", file=sys.stderr)
        resp = requests.get(file_url, timeout=300)
        resp.raise_for_status()
        encrypted_data = resp.content
        print(f"Downloaded {len(encrypted_data)} bytes", file=sys.stderr)

        if len(encrypted_data) < 100:
            return jsonify({
                'error': f'File too small ({len(encrypted_data)} bytes) - URL may have expired'
            }), 400

        # Decrypt
        print(f"Decrypting...", file=sys.stderr)
        decrypted = decrypt_media(encrypted_data, media_key_bytes, media_type)
        del encrypted_data
        print(f"Decrypted {len(decrypted)} bytes, returning raw binary", file=sys.stderr)

        # Retorna bytes raw
        return Response(
            decrypted,
            mimetype=mime_type,
            headers={
                'Content-Disposition': 'attachment',
                'Content-Length': str(len(decrypted))
            }
        )

    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Download failed: {str(e)}'}), 500
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
