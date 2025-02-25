from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from PIL import Image
import numpy as np
import base64
import io
import os
import logging
import traceback
from flask_cors import CORS

app = Flask(__name__)

# Configuration
KEY_FILE = "secret.key"
MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 Mo
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite à 16MB

# Désactiver les logs PIL
logging.getLogger("PIL").setLevel(logging.INFO)

# Générer et charger la clé une seule fois
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

key = load_key()
cipher = Fernet(key)

# Chiffrement du message
def encrypt_message(message):
    try:
        encrypted_message = cipher.encrypt(message.encode())
        return base64.b64encode(encrypted_message).decode()
    except Exception as e:
        logging.error("Erreur de chiffrement : ", exc_info=True)
        return None

# Déchiffrement du message
def decrypt_message(encrypted_message):
    try:
        decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))
        return decrypted_message.decode()
    except Exception as e:
        logging.error("Erreur de déchiffrement : ", exc_info=True)
        return None

# Cacher un message dans une image
def hide_message_in_image(image_bytes, message):
    try:
        if len(image_bytes) > MAX_IMAGE_SIZE:
            return "Erreur : Image trop grande (max 5 Mo)."

        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        data = np.array(img, dtype=np.uint8)

        binary_message = ''.join(format(ord(char), '08b') for char in message) + '11111111'

        if len(binary_message) > data.size:
            return "Erreur : Message trop long pour cette image."

        index = 0
        for i in range(data.shape[0]):
            for j in range(data.shape[1]):
                for k in range(3):
                    if index < len(binary_message):
                        data[i, j, k] = (data[i, j, k] & 0xFE) | int(binary_message[index])
                        index += 1
                    else:
                        break

        encrypted_img = Image.fromarray(data)
        img_byte_arr = io.BytesIO()
        encrypted_img.save(img_byte_arr, format="PNG")
        return img_byte_arr.getvalue()
    except Exception as e:
        logging.error("Erreur dans hide_message_in_image : ", exc_info=True)
        return None

# Extraire un message caché dans une image
def extract_message_from_image(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        data = np.array(img, dtype=np.uint8)

        binary_message = "".join(str(data[i, j, k] & 1) for i in range(data.shape[0]) for j in range(data.shape[1]) for k in range(3))

        bytes_message = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
        chars = []
        for byte in bytes_message:
            if byte == '11111111':
                break
            chars.append(chr(int(byte, 2)))

        return ''.join(chars) if chars else None
    except Exception as e:
        logging.error("Erreur dans extract_message_from_image : ", exc_info=True)
        return None

# Endpoint pour chiffrer et cacher un message dans une image
@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        if 'image' not in request.files or 'message' not in request.form:
            return jsonify({"error": "Image ou message manquant"}), 400

        file = request.files['image']
        message = request.form['message']

        if file.content_length > MAX_IMAGE_SIZE:
            return jsonify({"error": "Image trop grande (max 5 Mo)"}), 400

        encrypted_message = encrypt_message(message)
        if encrypted_message is None:
            return jsonify({"error": "Échec du chiffrement"}), 500

        encrypted_image = hide_message_in_image(file.read(), encrypted_message)
        if encrypted_image is None:
            return jsonify({"error": "Échec du masquage du message"}), 500

        return jsonify({"encrypted_image": base64.b64encode(encrypted_image).decode()})
    except Exception as e:
        logging.error("Erreur dans /encrypt : ", exc_info=True)
        return jsonify({"error": "Erreur interne"}), 500

# Endpoint pour extraire et décrypter un message caché dans une image
@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        if 'image' not in request.files:
            return jsonify({"error": "Image manquante"}), 400

        file = request.files['image']
        hidden_message = extract_message_from_image(file.read())

        if hidden_message is None:
            return jsonify({"error": "Aucun message trouvé"}), 400

        decrypted_message = decrypt_message(hidden_message)
        if decrypted_message is None:
            return jsonify({"error": "Échec du déchiffrement"}), 400

        return jsonify({"message": decrypted_message})
    except Exception as e:
        logging.error("Erreur dans /decrypt : ", exc_info=True)
        return jsonify({"error": "Erreur interne"}), 500

# Test de connexion
@app.route('/')
def home():
    return "Flask fonctionne !"

# Gestion des erreurs globales
@app.errorhandler(Exception)
def handle_exception(e):
    logging.error("Erreur détectée : ", exc_info=True)
    return jsonify({"error": "Erreur interne du serveur"}), 500

if __name__ == "__main__":
    app.run()
    CORS(app)
