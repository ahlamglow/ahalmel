import { generateKeyPairSync, publicEncrypt, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

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

        // Generate AES key and IV
        const aesKey = randomBytes(32);
        const iv = randomBytes(16);

        // Function to encrypt and decrypt values
        const encryptAndDecrypt = (key, value) => {
            const cipher = createCipheriv('aes-256-cbc', aesKey, iv);
            let encryptedValue = cipher.update(String(value), 'utf8', 'base64');
            encryptedValue += cipher.final('base64');
            encryptedItem[key] = encryptedValue;

            const decipher = createDecipheriv('aes-256-cbc', aesKey, iv);
            let decryptedValue = decipher.update(encryptedValue, 'base64', 'utf8');
            decryptedValue += decipher.final('utf8');
            decryptedItem[key] = decryptedValue;
        };

        for (const [key, value] of Object.entries(item)) {
            if (typeof value === 'object' && value !== null) {
                const encryptedSubItem = {};
                const decryptedSubItem = {};

                for (const [subKey, subValue] of Object.entries(value)) {
                    encryptAndDecrypt(subKey, subValue);
                    encryptedSubItem[subKey] = encryptedItem[subKey];
                    decryptedSubItem[subKey] = decryptedItem[subKey];
                }

                encryptedItem[key] = encryptedSubItem;
                decryptedItem[key] = decryptedSubItem;
            } else {
                encryptAndDecrypt(key, value);
            }
        }

        // Encrypt AES key with RSA
        const encryptedAesKey = publicEncrypt(publicKey, aesKey);
        encryptedItem['aesKey'] = encryptedAesKey.toString('base64');
        encryptedItem['iv'] = iv.toString('base64');

        decryptedData.push(decryptedItem);
        encryptedData.push(encryptedItem);
    });

    res.status(200).json({
        encryptedData,
        decryptedData,
        publicKey: publicKey.toString(),
        // privateKey: privateKey.toString(), // Uncomment if you need the private key in the response
    });
}