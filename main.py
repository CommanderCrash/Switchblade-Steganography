from flask import Flask, render_template, request, jsonify, send_file
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import io
import os
import logging

app = Flask(__name__)
app.secret_key = os.urandom(24)
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


BITS_PER_CHAR = 8
MESSAGE_HEADER = "-----BEGIN MESSAGE-----"
MESSAGE_BORDER = "|"

class Steganography:
    @staticmethod
    def encode(image: Image.Image, message: str, password: str) -> Image.Image:
        try:
            # Convert to RGBA to match browser's canvas format
            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            # Get the image data as a numpy array
            pixels = np.array(image)
            height, width = pixels.shape[:2]

            # First encrypt the message using AES (crypto-js compatible)
            key = SHA256.new(password.encode()).digest()
            cipher = AES.new(key, AES.MODE_CBC)
            # Add manual PKCS7 padding
            pad_length = 16 - (len(message.encode()) % 16)
            padded_message = message.encode() + bytes([pad_length] * pad_length)
            encrypted = cipher.encrypt(padded_message)

            # Format exactly like crypto-js
            iv_b64 = base64.b64encode(cipher.iv).decode('utf-8')
            ct_b64 = base64.b64encode(encrypted).decode('utf-8')
            ciphertext = f"{iv_b64}:{ct_b64}"

            # Format message
            formatted_msg = f"{MESSAGE_HEADER}|{len(ciphertext)}|{ciphertext}"
            logger.debug(f"Formatted message: {formatted_msg}")

            # Convert to binary
            binary_message = ''
            for char in formatted_msg:
                binary_message += format(ord(char), '08b')

            if len(binary_message) > width * height * 3:  # * 3 because we skip alpha
                raise ValueError("Message too large for image")

            # Create a copy and ensure alpha channel is 255
            modified = pixels.copy()
            modified[..., 3] = 255  # Set all alpha values to 255

            # Modify pixel data
            binary_index = 0
            for i in range(modified.size):
                if i % 4 == 3:  # Skip alpha channel
                    continue
                if binary_index < len(binary_message):
                    current_value = modified.flat[i]
                    message_bit = int(binary_message[binary_index])
                    # Only modify if necessary
                    if (current_value & 1) != message_bit:
                        modified.flat[i] = (current_value & ~1) | message_bit
                    binary_index += 1

            return Image.fromarray(modified)

        except Exception as e:
            logger.error(f"Encoding error: {str(e)}")
            raise

    @staticmethod
    def decode(image: Image.Image, password: str) -> str:
        try:
            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            pixels = np.array(image)
            binary = ''

            # Extract bits
            for i in range(pixels.size):
                if i % 4 == 3:  # Skip alpha channel
                    continue
                binary += str(pixels.flat[i] & 1)

            # Convert binary to text in chunks of 8 bits
            text = ''
            for i in range(0, len(binary), 8):
                if i + 8 <= len(binary):
                    text += chr(int(binary[i:i+8], 2))

            # Look for header
            if not text.startswith(MESSAGE_HEADER):
                return "Message not found in the image"

            # Parse message parts
            parts = text.split(MESSAGE_BORDER)
            if len(parts) < 3:
                return "Message not found in the image"

            try:
                message_length = int(parts[1])
                encrypted_message = parts[2][:message_length]

                # Split IV and ciphertext
                iv_b64, ct_b64 = encrypted_message.split(':')
                iv = base64.b64decode(iv_b64)
                ct = base64.b64decode(ct_b64)

                # Decrypt
                key = SHA256.new(password.encode()).digest()
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(ct)

                # Remove PKCS7 padding
                padding_length = decrypted[-1]
                message = decrypted[:-padding_length].decode()

                return message

            except Exception as e:
                logger.error(f"Decryption error: {str(e)}")
                return "Invalid password or corrupted message"

        except Exception as e:
            logger.error(f"Decoding error: {str(e)}")
            return "Message not found in the image"


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lock', methods=['POST'])
def lock():
    try:
        if 'image' not in request.files:
            return 'No image file uploaded', 400

        image_file = request.files['image']
        message = request.form.get('message', '')
        password = request.form.get('password', '')

        if not message:
            return 'No message provided', 400

        if not password:
            return 'Password is required', 400

        # Load and process image
        image = Image.open(image_file)
        logger.debug(f"Loaded image: {image.size}, {image.mode}")

        # Encode message
        stego_image = Steganography.encode(image, message, password)

        # Save to buffer
        img_buffer = io.BytesIO()
        stego_image.save(img_buffer, format='PNG', optimize=False)
        img_buffer.seek(0)

        return send_file(
            img_buffer,
            mimetype='image/png',
            as_attachment=True,
            download_name='encoded_image.png'
        )

    except Exception as e:
        logger.error(f"Error in lock route: {str(e)}")
        return str(e), 400

@app.route('/unlock', methods=['POST'])
def unlock():
    try:
        if 'image' not in request.files:
            return 'No image file uploaded', 400

        image_file = request.files['image']
        password = request.form.get('password', '')

        if not password:
            return 'Password is required', 400

        # Load stego image
        stego_image = Image.open(image_file)
        logger.debug(f"Loaded stego image: {stego_image.size}, {stego_image.mode}")

        # Extract message
        message = Steganography.decode(stego_image, password)
        return jsonify({'message': message})

    except Exception as e:
        logger.error(f"Error in unlock route: {str(e)}")
        return "Message not found in the image", 400

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5031)
