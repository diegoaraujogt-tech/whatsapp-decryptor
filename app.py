from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaInMemoryUpload, MediaIoBaseUpload
import base64
import hashlib
import hmac as hmac_module
import requests
import json
import os
import sys
import time
import io
import subprocess
import tempfile

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

    # Remove MAC (ultimos 10 bytes)
    file_data = encrypted_data[:-10]

    # Garante multiplo de 16 bytes pro AES CBC
    remainder = len(file_data) % 16
    if remainder != 0:
        file_data = file_data[:-(remainder)]

    cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(file_data)
    decrypted = aes_unpad(decrypted)
    return decrypted


def download_file(url, max_retries=5):
    """Download usando curl - mais robusto que requests pra arquivos grandes"""
    for attempt in range(max_retries):
        try:
            print(f"  Download attempt {attempt + 1}/{max_retries}...", file=sys.stderr)

            # Usa curl que e muito mais robusto pra downloads grandes
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.enc')
            tmp.close()

            result = subprocess.run(
                [
                    'curl', '-L', '-f', '-s',
                    '--retry', '3',
                    '--retry-delay', '5',
                    '--connect-timeout', '30',
                    '--max-time', '900',
                    '-o', tmp.name,
                    url
                ],
                capture_output=True,
                timeout=960
            )

            if result.returncode != 0:
                error_msg = result.stderr.decode('utf-8', errors='replace')
                print(f"  curl failed (code {result.returncode}): {error_msg[:100]}", file=sys.stderr)
                os.unlink(tmp.name)
                if attempt < max_retries - 1:
                    time.sleep(3 * (attempt + 1))
                    continue
                raise Exception(f"curl failed after {max_retries} attempts: {error_msg[:200]}")

            file_size = os.path.getsize(tmp.name)
            print(f"  Downloaded {file_size} bytes ({file_size / 1024 / 1024:.1f} MB)", file=sys.stderr)

            if file_size < 100:
                os.unlink(tmp.name)
                raise Exception(f"File too small ({file_size} bytes) - URL may have expired")

            with open(tmp.name, 'rb') as f:
                data = f.read()
            os.unlink(tmp.name)
            return data

        except subprocess.TimeoutExpired:
            print(f"  Timeout on attempt {attempt + 1}", file=sys.stderr)
            try:
                os.unlink(tmp.name)
            except:
                pass
            if attempt < max_retries - 1:
                time.sleep(5)
                continue
            raise Exception("Download timed out after all retries")

    raise Exception("Download failed after all retries")


def get_drive_service():
    creds_b64 = os.environ.get('GOOGLE_SERVICE_ACCOUNT_B64', '')
    if creds_b64:
        creds_json = base64.b64decode(creds_b64).decode('utf-8')
        creds_dict = json.loads(creds_json)
    else:
        creds_raw = os.environ.get('GOOGLE_SERVICE_ACCOUNT_JSON', '')
        if not creds_raw:
            raise Exception('No service account credentials found')
        creds_dict = json.loads(creds_raw)

    if 'private_key' in creds_dict:
        creds_dict['private_key'] = creds_dict['private_key'].replace('\\n', '\n')

    credentials = service_account.Credentials.from_service_account_info(
        creds_dict,
        scopes=['https://www.googleapis.com/auth/drive']
    )
    return build('drive', 'v3', credentials=credentials)


def upload_to_drive(file_data, file_name, mime_type, folder_id):
    service = get_drive_service()
    file_metadata = {
        'name': file_name,
        'parents': [folder_id]
    }
    media = MediaIoBaseUpload(
        io.BytesIO(file_data),
        mimetype=mime_type,
        resumable=True,
        chunksize=10 * 1024 * 1024
    )
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id, name, webViewLink, size',
        supportsAllDrives=True
    ).execute()
    return file


@app.route('/')
def home():
    return 'WhatsApp Decryptor OK - v9.0 (curl download + chunked upload)'


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

        print(f"=== DECRYPT-AND-UPLOAD v9.0 ===", file=sys.stderr)
        print(f"URL: {file_url[:80]}...", file=sys.stderr)
        print(f"MediaType: {media_type}", file=sys.stderr)
        print(f"FileName: {file_name}", file=sys.stderr)
        print(f"FolderID: {folder_id}", file=sys.stderr)

        if not file_url:
            return jsonify({'error': 'url is required'}), 400
        if not media_key_b64:
            return jsonify({'error': 'mediaKey is required'}), 400
        if not folder_id:
            return jsonify({'error': 'folderId is required'}), 400

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

        # Step 1: Download com curl
        print(f"Step 1: Downloading with curl...", file=sys.stderr)
        encrypted_data = download_file(file_url)
        print(f"Downloaded {len(encrypted_data)} bytes ({len(encrypted_data) / 1024 / 1024:.1f} MB)", file=sys.stderr)

        # Step 2: Decrypt
        print(f"Step 2: Decrypting...", file=sys.stderr)
        decrypted = decrypt_media(encrypted_data, media_key_bytes, media_type)
        del encrypted_data
        print(f"Decrypted {len(decrypted)} bytes ({len(decrypted) / 1024 / 1024:.1f} MB)", file=sys.stderr)

        # Step 3: Upload to Drive
        print(f"Step 3: Uploading to Drive...", file=sys.stderr)
        drive_file = upload_to_drive(decrypted, file_name, mime_type, folder_id)
        del decrypted
        print(f"Done! File ID: {drive_file.get('id')}", file=sys.stderr)

        return jsonify({
            'success': True,
            'fileId': drive_file.get('id'),
            'fileName': drive_file.get('name'),
            'fileLink': drive_file.get('webViewLink'),
            'fileSize': drive_file.get('size')
        })

    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500


@app.route('/test-drive', methods=['GET'])
def test_drive():
    try:
        folder_id = request.args.get('folder', '1khgyT1zsLiBJH1QxoMuhF1yjc66Jq8jf')
        service = get_drive_service()
        folder = service.files().get(
            fileId=folder_id,
            supportsAllDrives=True,
            fields='id, name, mimeType'
        ).execute()
        return jsonify({'success': True, 'folder': folder})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
