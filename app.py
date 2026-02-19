from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaInMemoryUpload
import base64
import hashlib
import hmac as hmac_module
import requests
import json
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


def get_drive_service():
    creds_json = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON', '')
    if not creds_json:
        raise Exception('GOOGLE_SERVICE_ACCOUNT_JSON environment variable not set')

    try:
        creds_dict = json.loads(creds_json)
    except json.JSONDecodeError as e:
        raise Exception(f'Invalid JSON in GOOGLE_SERVICE_ACCOUNT_JSON: {str(e)}')

    # Fix escaped newlines in private_key
    if 'private_key' in creds_dict:
        pk = creds_dict['private_key']
        # Handle double-escaped newlines from env vars
        pk = pk.replace('\\n', '\n')
        # Ensure it starts and ends properly
        if not pk.startswith('-----BEGIN'):
            raise Exception(f'private_key does not start with BEGIN marker. First 50 chars: {pk[:50]}')
        creds_dict['private_key'] = pk

    credentials = service_account.Credentials.from_service_account_info(
        creds_dict,
        scopes=['https://www.googleapis.com/auth/drive.file']
    )
    return build('drive', 'v3', credentials=credentials)


def upload_to_drive(file_data, file_name, mime_type, folder_id):
    service = get_drive_service()
    file_metadata = {
        'name': file_name,
        'parents': [folder_id]
    }
    media = MediaInMemoryUpload(file_data, mimetype=mime_type, resumable=True)
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id, name, webViewLink, size'
    ).execute()
    return file


@app.route('/')
def home():
    return 'WhatsApp Decryptor OK - v4.1 (Direct Drive Upload)'


@app.route('/decrypt-and-upload', methods=['POST'])
def decrypt_and_upload():
    try:
        data = request.json
        file_url = data.get('url', '')
        media_key_b64 = data.get('mediaKey', '')
        media_type = data.get('mediaType', 'video')
        file_name = data.get('fileName', 'video.mp4')
        folder_id = data.get('folderId', '')
        mime_type = data.get('mimeType', 'video/mp4')

        print(f"=== DECRYPT-AND-UPLOAD v4.1 ===", file=sys.stderr)
        print(f"URL: {file_url[:80]}...", file=sys.stderr)
        print(f"MediaType: {media_type}", file=sys.stderr)
        print(f"FileName: {file_name}", file=sys.stderr)
        print(f"FolderID: {folder_id}", file=sys.stderr)
        print(f"MediaKey: {media_key_b64}", file=sys.stderr)
        print(f"MediaKey length: {len(media_key_b64)} chars", file=sys.stderr)

        if not file_url:
            return jsonify({'error': 'url is required'}), 400
        if not media_key_b64:
            return jsonify({'error': 'mediaKey is required'}), 400
        if not folder_id:
            return jsonify({'error': 'folderId is required'}), 400

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

        if len(encrypted_data) < 11:
            return jsonify({'error': f'File too small: {len(encrypted_data)} bytes'}), 400

        # Step 2: Decrypt
        print(f"Step 2: Decrypting...", file=sys.stderr)
        decrypted = decrypt_media(encrypted_data, media_key_bytes, media_type)
        print(f"Decrypted {len(decrypted)} bytes", file=sys.stderr)
        del encrypted_data

        # Step 3: Upload
        print(f"Step 3: Uploading to Drive...", file=sys.stderr)
        try:
            drive_file = upload_to_drive(decrypted, file_name, mime_type, folder_id)
        except Exception as e:
            print(f"DRIVE ERROR: {str(e)}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            return jsonify({'error': f'Drive upload failed: {str(e)}'}), 500

        print(f"Done! File ID: {drive_file.get('id')}", file=sys.stderr)
        del decrypted

        return jsonify({
            'success': True,
            'fileId': drive_file.get('id'),
            'fileName': drive_file.get('name'),
            'fileLink': drive_file.get('webViewLink'),
            'fileSize': drive_file.get('size')
        })

    except requests.exceptions.RequestException as e:
        print(f"DOWNLOAD ERROR: {str(e)}", file=sys.stderr)
        return jsonify({'error': f'Download failed: {str(e)}'}), 500
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
