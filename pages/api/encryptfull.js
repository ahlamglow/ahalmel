import { generateKeyPairSync, publicEncrypt, privateDecrypt } from 'crypto';

export default function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Only POST requests allowed' });
    }

    const { data } = req.body;
    if (!data || !Array.isArray(data)) {
        return res.status(400).json({ message: 'Data is required and should be an array' });
    }

    // Generate RSA key pair
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'pkcs1',
            format: 'pem',
        },
        privateKeyEncoding: {
            type: 'pkcs1',
            format: 'pem',
        },
    });

    const encryptedData = [];
    const decryptedData = [];

    data.forEach((item) => {
        const encryptedItem = {};
        const decryptedItem = {};

        for (const [key, value] of Object.entries(item)) {
            // Encrypt data with the public key
            const encryptedValue = publicEncrypt(publicKey, Buffer.from(String(value)));
            encryptedItem[key] = encryptedValue.toString('base64');

            // Decrypt data with the private key (for demonstration purposes)
            const decryptedValue = privateDecrypt(privateKey, encryptedValue);
            decryptedItem[key] = decryptedValue.toString();
        }

        encryptedData.push(encryptedItem);
        decryptedData.push(decryptedItem);
    });

    res.status(200).json({
        encryptedData,
        decryptedData,
        publicKey: publicKey.toString(),
        privateKey: privateKey.toString(),
    });
}