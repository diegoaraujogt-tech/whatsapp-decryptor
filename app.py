from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64
import hashlib
import hmac as hmac_module
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
    # Extract step: HMAC-SHA256 with zero salt
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
    pad_len = s[-1]
    if pad_len < 1 or pad_len > 16:
        return s
    # Verify padding bytes are all the same
    if s[-pad_len:] != bytes([pad_len]) * pad_len:
        return s
    return s[:-pad_len]


def decrypt_media(encrypted_data, media_key_bytes, media_type="video"):
    """Decrypt WhatsApp media using the correct HKDF-based algorithm"""
    # Step 1: Expand mediaKey to 112 bytes using HKDF
    info = APP_INFO.get(media_type, b"WhatsApp Video Keys")
    media_key_expanded = hkdf_expand(media_key_bytes, 112, info)
    
    # Step 2: Split expanded key
    iv = media_key_expanded[:16]
    cipher_key = media_key_expanded[16:48]
    mac_key = media_key_expanded[48:80]
    # ref_key = media_key_expanded[80:112]  # unused
    
    # Step 3: Separate file data and MAC (last 10 bytes are MAC)
    file_data = encrypted_data[:-10]
    mac = encrypted_data[-10:]
    
    # Step 4: Decrypt with AES-CBC
    cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(file_data)
    
    # Step 5: Remove PKCS7 padding
    decrypted = aes_unpad(decrypted)
    
    return decrypted


@app.route('/')
def home():
    return 'WhatsApp Decryptor OK'


@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        
        encrypted_b64 = data.get('encryptedData', '')
        media_key_b64 = data.get('mediaKey', '')
        media_type = data.get('mediaType', 'video')
        
        print(f"=== DECRYPT REQUEST ===", file=sys.stderr)
        print(f"MediaKey b64 length: {len(media_key_b64)}", file=sys.stderr)
        print(f"EncryptedData b64 length: {len(encrypted_b64)}", file=sys.stderr)
        print(f"MediaType: {media_type}", file=sys.stderr)
        
        encrypted_data = base64.b64decode(encrypted_b64)
        media_key_bytes = base64.b64decode(media_key_b64)
        
        print(f"Encrypted bytes: {len(encrypted_data)}", file=sys.stderr)
        print(f"MediaKey bytes: {len(media_key_bytes)}", file=sys.stderr)
        
        if len(encrypted_data) < 11:
            return jsonify({'error': 'Encrypted data too small'}), 400
        
        if len(media_key_bytes) != 32:
            return jsonify({'error': f'Invalid media key length: {len(media_key_bytes)}, expected 32'}), 400
        
        decrypted = decrypt_media(encrypted_data, media_key_bytes, media_type)
        
        print(f"Decrypted bytes: {len(decrypted)}", file=sys.stderr)
        print(f"First 4 bytes (hex): {decrypted[:4].hex()}", file=sys.stderr)
        
        return jsonify({
            'decryptedData': base64.b64encode(decrypted).decode('utf-8')
        })
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    port = int(__import__('os').environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
