from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64
import sys

app = Flask(__name__)

@app.route('/')
def home():
    return 'WhatsApp Decryptor OK'

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.json
        
        # Debug - vê o que chegou
        print("=== DECRYPT REQUEST ===", file=sys.stderr)
        print(f"MediaKey length: {len(data.get('mediaKey', ''))}", file=sys.stderr)
        print(f"EncryptedData length: {len(data.get('encryptedData', ''))}", file=sys.stderr)
        
        encrypted_data = base64.b64decode(data['encryptedData'])
        media_key = base64.b64decode(data['mediaKey'])
        
        print(f"Decoded encrypted length: {len(encrypted_data)}", file=sys.stderr)
        print(f"Decoded encrypted % 16: {len(encrypted_data) % 16}", file=sys.stderr)
        print(f"Decoded key length: {len(media_key)}", file=sys.stderr)
        
        # Adiciona padding se necessário
        remainder = len(encrypted_data) % 16
        if remainder != 0:
            encrypted_data += b'\x00' * (16 - remainder)
            print(f"Added padding: {16 - remainder} bytes", file=sys.stderr)
        
        iv = media_key[:16]
        key = media_key[16:48]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        decrypted = decrypted.rstrip(b'\x00')
        
        return jsonify({
            'decryptedData': base64.b64encode(decrypted).decode('utf-8')
        })
    except Exception as e:
        print(f"ERROR: {str(e)}", file=sys.stderr)
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
