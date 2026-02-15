from flask import Flask, request, jsonify
from Crypto.Cipher import AES
import base64

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
        
        iv = media_key[:16]
        key = media_key[16:48]
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_data)
        
        # WhatsApp não usa padding padrão, então não fazemos unpad
        # Apenas remove possíveis bytes nulos do final
        decrypted = decrypted.rstrip(b'\x00')
        
        return jsonify({
            'decryptedData': base64.b64encode(decrypted).decode('utf-8')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)
