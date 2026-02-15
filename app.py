from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64
import hashlib

app = Flask(__name__)

@app.route('/')
def home():
    return 'WhatsApp Decryptor OK'

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        encrypted_data = base64.b64decode(data['encryptedData'])
        media_key = base64.b64decode(data['mediaKey'])
        
        # WhatsApp usa expanded key derivation
        expanded_key = hashlib.sha256(media_key).digest()
        iv = expanded_key[:16]
        cipher_key = expanded_key[16:48]
        
        # Remove MAC se existir (últimos 10 bytes)
        if len(encrypted_data) > 10:
            encrypted_data = encrypted_data[:-10]
        
        # Padding
        remainder = len(encrypted_data) % 16
        if remainder != 0:
            encrypted_data += b'\x00' * (16 - remainder)
        
        cipher = AES.new(cipher_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        
        # Remove padding
        decrypted = decrypted.rstrip(b'\x00')
        
        return jsonify({
            'decryptedData': base64.b64encode(decrypted).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
