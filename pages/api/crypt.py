from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as sym_padding
import base64
import os
import zlib
from tabulate import tabulate

# Génération des clés
private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
public_key = private_key.public_key()

# Sérialiser la clé publique
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

# Sérialiser la clé privée (à des fins de démonstration, normalement, on ne doit pas exposer la clé privée)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()).decode('utf-8')

print("Clé publique:")
print(public_pem)

print("\nClé privée:")
print(private_pem)


# Fonction pour chiffrer les données avec AES
def encrypt_data_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data


# Fonction pour déchiffrer les données avec AES
def decrypt_data_aes(encrypted_data, key):
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]

    cipher = Cipher(algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(
        encrypted_data) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(
        decrypted_padded_data) + unpadder.finalize()

    return decrypted_data


# Fonction pour chiffrer une clé symétrique avec RSA
def encrypt_key(key, public_key):
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
    return base64.b64encode(encrypted_key).decode('utf-8')


# Fonction pour déchiffrer une clé symétrique avec RSA
def decrypt_key(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(
        base64.b64decode(encrypted_key.encode()),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
    return decrypted_key


# Fonction pour compresser les données
def compress_data(data):
    return zlib.compress(data.encode())


# Fonction pour décompresser les données
def decompress_data(data):
    return zlib.decompress(data).decode()


# Fonction pour chiffrer les données
def encrypt_data(data, public_key):
    session_key = os.urandom(32)
    compressed_data = compress_data(data)
    encrypted_data = encrypt_data_aes(compressed_data, session_key)
    encrypted_session_key = encrypt_key(session_key, public_key)

    return base64.b64encode(encrypted_session_key.encode() + b"\n" +
                            base64.b64encode(encrypted_data)).decode('utf-8')


# Fonction pour déchiffrer les données
def decrypt_data(encrypted_data, private_key):
    encrypted_data = base64.b64decode(encrypted_data.encode())
    encrypted_session_key, encrypted_data = encrypted_data.split(b"\n", 1)
    session_key = decrypt_key(encrypted_session_key.decode('utf-8'),
                              private_key)
    decrypted_data = decrypt_data_aes(base64.b64decode(encrypted_data),
                                      session_key)
    decompressed_data = decompress_data(decrypted_data)

    return decompressed_data


# Exemple de données de formulaire (nous pourrions remplacer ceci par les données réelles)
form_data = {
    'name': 'Amélie',
    'email': 'amelie@example.com',
    'Tel': '0777777778888',
    'adresse': 'rue des papillons',
    'ville': 'rabat' * 20,
    'Code Postal': '1234',
    'Pays': 'maroc',
    'Date de naissance': '01/01/2002',
    'Sexe': 'femme',
    'Nationalité': 'marocaine',
}

# Chiffrement des données du formulaire
encrypted_form_data = {
    key: encrypt_data(value, public_key)
    for key, value in form_data.items()
}

# Ajouter les données personnelles et la clé publique dans une liste sous forme de tableau
personal_info_with_encryption = [
    ['public_key', public_pem], ['Donnée', 'Valeur chiffrée'],
    ['name', encrypted_form_data['name']],
    ['email',
     encrypted_form_data['email']], ['Tel', encrypted_form_data['Tel']],
    ['adresse', encrypted_form_data['adresse']],
    ['ville', encrypted_form_data['ville']],
    ['Code Postal', encrypted_form_data['Code Postal']],
    ['Pays', encrypted_form_data['Pays']],
    ['Date de naissance', encrypted_form_data['Date de naissance']],
    ['Sexe', encrypted_form_data['Sexe']],
    ['Nationalité', encrypted_form_data['Nationalité']]
]

print("Informations personnelles et clé publique:")
print(
    tabulate(personal_info_with_encryption,
             headers="firstrow",
             tablefmt="grid"))

# Déchiffrement des données avec la clé privée saisie manuellement
private_key_input = private_pem = input("\nEntrez votre clé privée (en PEM):\n")


# Charger la clé privée saisie par l'utilisateur
loaded_private_key = serialization.load_pem_private_key(
    private_key_input.encode('utf-8'),
    password=None,
    backend=default_backend())

# Déchiffrement des données
decrypted_form_data = {
    key: decrypt_data(value, loaded_private_key)
    for key, value in encrypted_form_data.items()
}

# Ajouter les données déchiffrées dans une liste sous forme de tableau
personal_info_decrypted = [['Donnée', 'Valeur déchiffrée'],
                           ['name', decrypted_form_data['name']],
                           ['email', decrypted_form_data['email']],
                           ['Tel', decrypted_form_data['Tel']],
                           ['adresse', decrypted_form_data['adresse']],
                           ['ville', decrypted_form_data['ville']],
                           ['Code Postal', decrypted_form_data['Code Postal']],
                           ['Pays', decrypted_form_data['Pays']],
                           [
                               'Date de naissance',
                               decrypted_form_data['Date de naissance']
                           ], ['Sexe', decrypted_form_data['Sexe']],
                           ['Nationalité', decrypted_form_data['Nationalité']]]

print("\nDonnées déchiffrées:")

print(tabulate(personal_info_decrypted, headers="firstrow", tablefmt="grid"))
