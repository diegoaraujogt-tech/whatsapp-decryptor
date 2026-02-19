from flask import Flask, request, jsonify, send_file
from Crypto.Cipher import AES
import base64
import hashlib
import hmac as hmac_module
import requests
import tempfile
import os
import sys

app = Flask(__name__)

# WhatsApp media type info strings for HKDF key expansion
APP_INFO = {
    "video": b"WhatsApp Video Keys",
    "image": b"WhatsApp Image Keys",
    "audio": b"WhatsApp Audio Keys",
    "document": b"WhatsApp Document Keys",
    "video/mp4": b"WhatsApp Video Keys",
    "image/jpeg": b"WhatsApp Image Keys",
    "image/webp": b"WhatsApp Image Keys",
    "image/png": b"WhatsApp Image Keys",
    "audio/aac": b"WhatsApp Audio Keys",
    "audio/ogg": b"WhatsApp Audio Keys",
    "audio/wav": b"WhatsApp Audio Keys",
    "application/pdf": b"WhatsApp Document Keys",
}


def hkdf_expand(key, length, app_info=b""):
    """HKDF key derivation as used by WhatsApp"""
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
    """Remove PKCS7 padding"""
    if len(s) == 0:
        return s
    pad_len = s[-1]
    if pad_len < 1 or pad_len > 16:
        return s
    if s[-pad_len:] != bytes([pad_len]) * pad_len:
        return s
    return s[:-pad_len]


def decrypt_media(encrypted_data, media_key_bytes, media_type="video"):
    """Decrypt WhatsApp media using HKDF-based algorithm"""
    info = APP_INFO.get(media_type, b"WhatsApp Video Keys")
    media_key_expanded = hkdf_expand(media_key_bytes, 112, info)

    iv = media_key_expanded[:16]
    cipher_key = media_key_expanded[16:48]

    # Last 10 bytes are MAC
    file_data = encrypted_data[:-10]

    cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(file_data)
    decrypted = aes_unpad(decrypted)

    return decrypted


@app.route('/')
def home():
    return 'WhatsApp Decryptor OK - v2 (URL mode)'


@app.route('/decrypt-url', methods=['POST'])
def decrypt_url():
    """Downloads .enc file from WhatsApp URL and returns decrypted binary file"""
    try:
        data = request.json
        file_url = data.get('url', '')
        media_key_b64 = data.get('mediaKey', '')
        media_type = data.get('mediaType', 'video')

        print(f"=== DECRYPT-URL REQUEST ===", file=sys.stderr)
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
        resp = requests.get(file_url, timeout=120)
        resp.raise_for_status()

        encrypted_data = resp.content
        print(f"Downloaded {len(encrypted_data)} bytes", file=sys.stderr)

        if len(encrypted_data) < 11:
            return jsonify({'error': f'Downloaded file too small: {len(encrypted_data)} bytes'}), 400

        # Decrypt
        decrypted = decrypt_media(encrypted_data, media_key_bytes, media_type)
        print(f"Decrypted {len(decrypted)} bytes", file=sys.stderr)

        # Write to temp file and send as binary response
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.dec')
        tmp.write(decrypted)
        tmp.close()

        # Determine mime type
        mime_map = {
            'video': 'video/mp4',
            'image': 'image/jpeg',
            'audio': 'audio/ogg',
            'document': 'application/octet-stream',
        }
        mime = mime_map.get(media_type, 'application/octet-stream')

        response = send_file(
            tmp.name,
            mimetype=mime,
            as_attachment=True,
            download_name=f'decrypted.{media_type}'
        )

        # Clean up temp file after sending
        @response.call_on_close
        def cleanup():
            try:
                os.unlink(tmp.name)
            except:
                pass

        return response

    except requests.exceptions.RequestException as e:
        print(f"DOWNLOAD ERROR: {str(e)}", file=sys.stderr)
        return jsonify({'error': f'Failed to download file: {str(e)}'}), 500
    except Exception as e:
        print(f"ERROR in /decrypt-url: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
