import { generateKeyPairSync, publicEncrypt, privateDecrypt, randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export default function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Seules les requêtes POST sont autorisées' });
    }

    const { data } = req.body;
    if (!data || !Array.isArray(data)) {
        return res.status(400).json({ message: 'Les données sont requises et doivent être un tableau' });
    }

    // Générer une paire de clés RSA
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

        // Générer la clé AES et le IV
        const aesKey = randomBytes(32);
        const iv = randomBytes(16);

        const encryptAndDecrypt = (key, value) => {
            // Chiffrer la valeur avec AES
            const cipher = createCipheriv('aes-256-cbc', aesKey, iv);
            let encryptedValue = cipher.update(String(value), 'utf8', 'base64');
            encryptedValue += cipher.final('base64');
            encryptedItem[key] = encryptedValue;

            // Déchiffrer la valeur avec AES
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

        // Gérer l'objet vidéo s'il est présent
        if (item.video) {
            const encryptedVideo = {};
            const decryptedVideo = {};

            for (const [videoKey, videoValue] of Object.entries(item.video)) {
                encryptAndDecrypt(videoKey, videoValue);
                encryptedVideo[videoKey] = encryptedItem[videoKey];
                decryptedVideo[videoKey] = decryptedItem[videoKey];
            }

            encryptedItem['video'] = encryptedVideo;
            decryptedItem['video'] = decryptedVideo;
        }

        // Chiffrer la clé AES avec RSA
        const encryptedAesKey = publicEncrypt(publicKey, aesKey);
        encryptedItem['aesKey'] = encryptedAesKey.toString('base64');
        encryptedItem['iv'] = iv.toString('base64');

        decryptedData.push(decryptedItem);
        encryptedData.push(encryptedItem);
    });

    res.status(200).json({
        npm
        encryptedData,
        decryptedData,
        publicKey: publicKey.toString(),
        //privateKey: privateKey.toString(),
    });
}