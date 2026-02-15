const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json({ limit: '100mb' }));

app.post('/decrypt', (req, res) => {
  try {
    const { encryptedData, mediaKey } = req.body;
    const encBuffer = Buffer.from(encryptedData, 'base64');
    const keyBuffer = Buffer.from(mediaKey, 'base64');
    const iv = keyBuffer.slice(0, 16);
    const cipherKey = keyBuffer.slice(16, 48);
    const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey, iv);
    const decrypted = Buffer.concat([decipher.update(encBuffer), decipher.final()]);
    res.json({ decryptedData: decrypted.toString('base64') });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/', (req, res) => res.send('WhatsApp Decryptor OK'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
