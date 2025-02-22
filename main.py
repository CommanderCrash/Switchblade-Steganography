#!/usr/bin/python3

# By Commander Crash

from flask import Flask, render_template, request, jsonify, send_file
from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import base64
import io
import os
import cv2
import logging
import time
from werkzeug.utils import secure_filename
import traceback

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = None  # No file size limit
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = os.urandom(24)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Emoji steganography functions
def vstrans(x):
    """Transform byte into variation selector"""
    if x < 16:
        return x + 0xFE00
    else:
        return x - 16 + 0xE0100

def load_image_file(file_path):
    """
    Load an image file (including GIF) and convert it to a format suitable for cv2
    Returns: numpy array in BGR format
    """
    try:
        # Open with PIL first (handles GIFs better)
        pil_image = Image.open(file_path)

        # If it's a GIF, take the first frame
        if getattr(pil_image, 'is_animated', False):
            pil_image.seek(0)

        # Convert to RGB and then to numpy array
        if pil_image.mode != 'RGB':
            pil_image = pil_image.convert('RGB')

        # Convert to numpy array
        image_array = np.array(pil_image)

        # Convert RGB to BGR for cv2
        image_array = cv2.cvtColor(image_array, cv2.COLOR_RGB2BGR)

        return image_array
    except Exception as e:
        logger.error(f"Error loading image: {str(e)}")
        return None

def encode_emoji_message(carrier: str, message: str) -> str:
    """Encode a message using variation selectors"""
    try:
        message_bytes = message.encode()
        result = carrier
        for byte in message_bytes:
            vs_code = vstrans(byte)
            result += chr(vs_code)
        return result
    except Exception as e:
        logger.error(f"Emoji encoding error: {e}")
        return None

def decode_emoji_message(text: str) -> str:
    """Decode message from variation selectors"""
    try:
        out = []
        for char in text[1:]:
            code = ord(char)
            if 0xFE00 <= code <= 0xFE0F:
                out.append(code - 0xFE00)
            elif 0xE0100 <= code <= 0xE01EF:
                out.append(code - 0xE0100 + 16)
        if out:
            return bytes(out).decode()
        return "No hidden message found"
    except Exception as e:
        logger.error(f"Emoji decoding error: {e}")
        return "Error decoding message"

# Image message steganography class
class ImageMessageSteg:
    @staticmethod
    def encode(image: Image.Image, message: str, password: str) -> Image.Image:
        try:
            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            pixels = np.array(image)
            height, width = pixels.shape[:2]

            key = SHA256.new(password.encode()).digest()
            cipher = AES.new(key, AES.MODE_CBC)
            pad_length = 16 - (len(message.encode()) % 16)
            padded_message = message.encode() + bytes([pad_length] * pad_length)
            encrypted = cipher.encrypt(padded_message)

            iv_b64 = base64.b64encode(cipher.iv).decode('utf-8')
            ct_b64 = base64.b64encode(encrypted).decode('utf-8')
            ciphertext = f"{iv_b64}:{ct_b64}"

            formatted_msg = f"-----BEGIN MESSAGE-----|{len(ciphertext)}|{ciphertext}"
            binary_message = ''.join(format(ord(char), '08b') for char in formatted_msg)

            if len(binary_message) > width * height * 3:
                raise ValueError("Message too large for image")

            modified = pixels.copy()
            modified[..., 3] = 255

            binary_index = 0
            for i in range(modified.size):
                if i % 4 == 3:
                    continue
                if binary_index < len(binary_message):
                    current_value = modified.flat[i]
                    message_bit = int(binary_message[binary_index])
                    if (current_value & 1) != message_bit:
                        modified.flat[i] = (current_value & ~1) | message_bit
                    binary_index += 1

            return Image.fromarray(modified)
        except Exception as e:
            logger.error(f"Image message encoding error: {e}")
            raise

    @staticmethod
    def decode(image: Image.Image, password: str) -> str:
        try:
            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            pixels = np.array(image)
            binary = ''.join(str(pixels.flat[i] & 1) for i in range(pixels.size) if i % 4 != 3)

            text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)
                          if i + 8 <= len(binary))

            if not text.startswith("-----BEGIN MESSAGE-----"):
                return "Message not found in the image"

            parts = text.split("|")
            if len(parts) < 3:
                return "Message not found in the image"

            try:
                message_length = int(parts[1])
                encrypted_message = parts[2][:message_length]

                iv_b64, ct_b64 = encrypted_message.split(':')
                iv = base64.b64decode(iv_b64)
                ct = base64.b64decode(ct_b64)

                key = SHA256.new(password.encode()).digest()
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(ct)

                padding_length = decrypted[-1]
                message = decrypted[:-padding_length].decode()

                return message
            except Exception as e:
                logger.error(f"Image message decryption error: {e}")
                return "Invalid password or corrupted message"
        except Exception as e:
            logger.error(f"Image message decoding error: {e}")
            return "Message not found in the image"

# File in image steganography class
class LSBSteg:
    def __init__(self, im):
        self.image = im
        self.height, self.width, self.nbchannels = im.shape
        self.size = self.width * self.height

        self.maskONEValues = [1,2,4,8,16,32,64,128]
        self.maskONE = self.maskONEValues.pop(0)

        self.maskZEROValues = [254,253,251,247,239,223,191,127]
        self.maskZERO = self.maskZEROValues.pop(0)

        self.curwidth = 0
        self.curheight = 0
        self.curchan = 0

    def put_binary_value(self, bits): #Put the bits in the image
        for c in bits:
            val = list(self.image[self.curheight,self.curwidth]) #Get the pixel value as a list
            if int(c) == 1:
                val[self.curchan] = int(val[self.curchan]) | self.maskONE #OR with maskONE
            else:
                val[self.curchan] = int(val[self.curchan]) & self.maskZERO #AND with maskZERO

            self.image[self.curheight,self.curwidth] = tuple(val)
            self.next_slot() #Move "cursor" to the next space

    def next_slot(self):#Move to the next slot were information can be taken or put
        if self.curchan == self.nbchannels-1: #Next Space is the following channel
            self.curchan = 0
            if self.curwidth == self.width-1: #Or the first channel of the next pixel of the same line
                self.curwidth = 0
                if self.curheight == self.height-1:#Or the first channel of the first pixel of the next line
                    self.curheight = 0
                    if self.maskONE == 128: #Mask 1000000, so the last mask
                        raise Exception("No available slot remaining (image filled)")
                    else: #Or instead of using the first bit start using the second and so on..
                        self.maskONE = self.maskONEValues.pop(0)
                        self.maskZERO = self.maskZEROValues.pop(0)
                else:
                    self.curheight +=1
            else:
                self.curwidth +=1
        else:
            self.curchan +=1

    def read_bit(self): #Read a single bit in the image
        val = self.image[self.curheight,self.curwidth][self.curchan]
        val = int(val) & self.maskONE
        self.next_slot()
        if val > 0:
            return "1"
        else:
            return "0"

    def read_byte(self):
        return self.read_bits(8)

    def read_bits(self, nb): #Read the given number of bits
        bits = ""
        for i in range(nb):
            bits += self.read_bit()
        return bits

    def byteValue(self, val):
        return self.binary_value(val, 8)

    def binary_value(self, val, bitsize): #Return the binary value of an int as a byte
        binval = bin(val)[2:]
        if len(binval) > bitsize:
            raise Exception("binary value larger than the expected size")
        while len(binval) < bitsize:
            binval = "0"+binval
        return binval

    def encode_text(self, txt):
        l = len(txt)
        binl = self.binary_value(l, 16) #Length coded on 2 bytes so the text size can be up to 65536 bytes long
        self.put_binary_value(binl) #Put text length coded on 4 bytes
        for char in txt: #And put all the chars
            c = ord(char)
            self.put_binary_value(self.byteValue(c))
        return self.image

    def decode_text(self):
        ls = self.read_bits(16) #Read the text size in bytes
        l = int(ls,2)
        i = 0
        unhideTxt = ""
        while i < l: #Read all bytes of the text
            tmp = self.read_byte() #So one byte
            i += 1
            unhideTxt += chr(int(tmp,2)) #Every chars concatenated to str
        return unhideTxt

    def encode_image(self, imtohide):
        w = imtohide.shape[1]
        h = imtohide.shape[0]
        if self.width*self.height*self.nbchannels < w*h*imtohide.shape[2]:
            raise Exception("Carrier image not big enough to hold all the data to steganography")
        binw = self.binary_value(w, 16) #Width coded on 2 bytes so width up to 65536
        binh = self.binary_value(h, 16)
        self.put_binary_value(binw) #Put width
        self.put_binary_value(binh) #Put height
        for h in range(imtohide.shape[0]): #Iterate over the whole image to put every pixel values
            for w in range(imtohide.shape[1]):
                for chan in range(imtohide.shape[2]):
                    val = imtohide[h,w][chan]
                    self.put_binary_value(self.byteValue(int(val)))
        return self.image

    def decode_image(self):
        width = int(self.read_bits(16),2) #Read 16bits and convert it in int
        height = int(self.read_bits(16),2)
        unhideimg = np.zeros((height,width,3), np.uint8) #Create an image in which we will put all the pixels read
        for h in range(height):
            for w in range(width):
                for chan in range(unhideimg.shape[2]):
                    val = list(unhideimg[h,w])
                    val[chan] = int(self.read_byte(),2) #Read the value
                    unhideimg[h,w] = tuple(val)
        return unhideimg

    def encode_binary(self, data):
        l = len(data)
        if self.width*self.height*self.nbchannels < l+64:
            raise Exception("Carrier image not big enough to hold all the data to steganography")
        self.put_binary_value(self.binary_value(l, 64))
        for byte in data:
            byte = byte if isinstance(byte, int) else ord(byte) # Compat py2/py3
            self.put_binary_value(self.byteValue(byte))
        return self.image

    def decode_binary(self):
        l = int(self.read_bits(64), 2)
        output = b""
        for i in range(l):
            output += bytearray([int(self.read_byte(),2)])
        return output
# Routes
@app.route('/')
def index():
    return render_template('index.html')

# Emoji steganography routes
@app.route('/encode_emoji', methods=['POST'])
def encode_emoji():
    data = request.json
    carrier = data.get('carrier', '')
    message = data.get('message', '')

    if not carrier:
        return jsonify({'error': 'Please select an emoji or letter first'}), 400
    if not message:
        return jsonify({'error': 'Please enter a message to hide'}), 400

    try:
        encoded = encode_emoji_message(carrier, message)
        if encoded:
            return jsonify({'result': encoded})
        else:
            return jsonify({'error': 'Encoding failed'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decode_emoji', methods=['POST'])
def decode_emoji():
    data = request.json
    text = data.get('text', '')

    if not text:
        return jsonify({'error': 'Please enter text to decode'}), 400

    try:
        decoded = decode_emoji_message(text)
        return jsonify({'result': decoded})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Image message steganography routes
@app.route('/encode_image_message', methods=['POST'])
def encode_image_message():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file uploaded'}), 400

        image_file = request.files['image']
        message = request.form.get('message', '')
        password = request.form.get('password', '')

        if not message:
            return jsonify({'error': 'No message provided'}), 400
        if not password:
            return jsonify({'error': 'Password is required'}), 400

        image = Image.open(image_file)
        stego_image = ImageMessageSteg.encode(image, message, password)

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
        return jsonify({'error': str(e)}), 400

@app.route('/decode_image_message', methods=['POST'])
def decode_image_message():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file uploaded'}), 400

        image_file = request.files['image']
        password = request.form.get('password', '')

        if not password:
            return jsonify({'error': 'Password is required'}), 400

        stego_image = Image.open(image_file)
        message = ImageMessageSteg.decode(stego_image, password)
        return jsonify({'message': message})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# File in image steganography routes
@app.route('/encode_file', methods=['POST'])
def encode_file():
    try:
        if 'carrier' not in request.files:
            return jsonify({'error': 'No carrier image provided'}), 400
        if 'file' not in request.files:
            return jsonify({'error': 'No file to hide provided'}), 400

        carrier_file = request.files['carrier']
        file_to_hide = request.files['file']

        # Check if the file is a GIF
        if carrier_file.filename.lower().endswith('.gif'):
            return jsonify({'error': 'GIF files are not supported as carrier images. Please use PNG or JPG files.'}), 400

        timestamp = int(time.time())
        carrier_filename = f"{timestamp}_carrier_{secure_filename(carrier_file.filename)}"
        carrier_path = os.path.join(app.config['UPLOAD_FOLDER'], carrier_filename)
        carrier_file.save(carrier_path)

        carrier_image = cv2.imread(carrier_path)

        # Add check for successful image loading
        if carrier_image is None:
            return jsonify({'error': 'Failed to load carrier image. Please ensure it is a valid PNG or JPG file.'}), 400

        file_data = file_to_hide.read()
        required_bits = len(file_data) * 8 + 64
        available_bits = carrier_image.shape[0] * carrier_image.shape[1] * 3

        if required_bits > available_bits:
            return jsonify({
                'error': f'File too large. Needs {required_bits} bits but only {available_bits} available'
            }), 400

        steg = LSBSteg(carrier_image)
        result_image = steg.encode_binary(file_data)

        output_filename = f"{timestamp}_encoded_{secure_filename(carrier_file.filename)}"
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)
        cv2.imwrite(output_path, result_image)

        with open(output_path, 'rb') as f:
            encoded_image = base64.b64encode(f.read()).decode('utf-8')

        return jsonify({
            'success': True,
            'image': encoded_image,
            'filename': output_filename,
            'originalFile': secure_filename(file_to_hide.filename),
            'fileSize': len(file_data),
            'bitsUsed': required_bits,
            'bitsAvailable': available_bits
        })

    except Exception as e:
        logger.error(f"File encoding error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/decode_file', methods=['POST'])
def decode_file():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image provided'}), 400

        image_file = request.files['image']
        image_filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        image_file.save(image_path)

        encoded_image = cv2.imread(image_path)
        steg = LSBSteg(encoded_image)
        decoded_data = steg.decode_binary()

        timestamp = int(time.time())
        output_filename = f'decoded_file_{timestamp}'
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename)

        with open(output_path, 'wb') as f:
            f.write(decoded_data)

        return jsonify({
            'success': True,
            'fileSize': len(decoded_data),
            'downloadPath': f'/download/{output_filename}'
        })
    except Exception as e:
        logger.error(f"File decoding error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download(filename):
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404

        return send_file(
            file_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        return jsonify({'error': 'Download failed'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5353)
