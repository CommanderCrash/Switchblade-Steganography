#!/usr/bin/python3

# By Commander Crash

from flask import Flask, render_template, request, jsonify, send_file, Response
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
import threading
from werkzeug.utils import secure_filename
import traceback
import multiprocessing

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = None  # No file size limit
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = os.urandom(24)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Dict to store processing status
process_status = {}

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
    def encode(image: Image.Image, message: str, password: str = None) -> Image.Image:
        try:
            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            pixels = np.array(image)
            height, width = pixels.shape[:2]

            # Handle message preparation based on password presence
            if password:
                # Encrypted mode
                key = SHA256.new(password.encode()).digest()
                cipher = AES.new(key, AES.MODE_CBC)
                pad_length = 16 - (len(message.encode()) % 16)
                padded_message = message.encode() + bytes([pad_length] * pad_length)
                encrypted = cipher.encrypt(padded_message)
                iv_b64 = base64.b64encode(cipher.iv).decode('utf-8')
                ct_b64 = base64.b64encode(encrypted).decode('utf-8')
                ciphertext = f"{iv_b64}:{ct_b64}"
                formatted_msg = f"-----BEGIN ENCRYPTED-----|{len(ciphertext)}|{ciphertext}"
            else:
                # Unencrypted mode
                formatted_msg = f"-----BEGIN PLAIN-----|{len(message)}|{message}"

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
    def decode(image: Image.Image, password: str = None) -> str:
        try:
            if image.mode != 'RGBA':
                image = image.convert('RGBA')

            pixels = np.array(image)
            binary = ''.join(str(pixels.flat[i] & 1) for i in range(pixels.size) if i % 4 != 3)

            text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary), 8)
                          if i + 8 <= len(binary))

            # Check message type
            if text.startswith("-----BEGIN ENCRYPTED-----"):
                if not password:
                    return "This message is encrypted. Please provide a password to decrypt."

                try:
                    parts = text.split("|")
                    if len(parts) < 3:
                        return "Invalid message format"

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

            elif text.startswith("-----BEGIN PLAIN-----"):
                try:
                    parts = text.split("|")
                    if len(parts) < 3:
                        return "Invalid message format"

                    message_length = int(parts[1])
                    message = parts[2][:message_length]
                    return message
                except Exception as e:
                    logger.error(f"Error decoding plain message: {e}")
                    return "Error decoding message"

            return "No message found in the image"

        except Exception as e:
            logger.error(f"Image message decoding error: {e}")
            return "Failed to decode message from image"

# File in image steganography class with performance improvements
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

        # For tracking progress
        self.total_pixels = self.width * self.height * self.nbchannels
        self.processed_pixels = 0
        self.task_id = None

    def update_progress(self):
        """Update the progress percentage"""
        if self.task_id:
            progress = min(100, int((self.processed_pixels / self.total_pixels) * 100))
            process_status[self.task_id]['progress'] = progress
            process_status[self.task_id]['status'] = f"Processing: {progress}% complete"

    def put_binary_value(self, bits): #Put the bits in the image
        for c in bits:
            val = list(self.image[self.curheight,self.curwidth]) #Get the pixel value as a list
            if int(c) == 1:
                val[self.curchan] = int(val[self.curchan]) | self.maskONE #OR with maskONE
            else:
                val[self.curchan] = int(val[self.curchan]) & self.maskZERO #AND with maskZERO

            self.image[self.curheight,self.curwidth] = tuple(val)
            self.next_slot() #Move "cursor" to the next space

            # Update progress every 10000 pixels
            self.processed_pixels += 1
            if self.task_id and self.processed_pixels % 10000 == 0:
                self.update_progress()

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
        try:
            val = self.image[self.curheight,self.curwidth][self.curchan]
            val = int(val) & self.maskONE
            self.next_slot()

            # Update progress every 10000 pixels
            self.processed_pixels += 1
            if self.task_id and self.processed_pixels % 10000 == 0:
                self.update_progress()

            if val > 0:
                return "1"
            else:
                return "0"
        except IndexError:
            # In case we try to access an invalid pixel
            raise Exception("No available slot remaining (image filled)")

    def read_byte(self):
        try:
            return self.read_bits(8)
        except Exception as e:
            # Propagate the error but with more context
            raise Exception(f"Failed to read byte: {str(e)}")

    def read_bits(self, nb): #Read the given number of bits
        bits = ""
        try:
            for i in range(nb):
                bits += self.read_bit()
            return bits
        except Exception as e:
            # Propagate the error but with context
            raise Exception(f"Failed to read {nb} bits (got {len(bits)} bits): {str(e)}")

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

        if self.task_id:
            process_status[self.task_id]['status'] = "Starting encoding process"

        # First, encode the length of data as a 64-bit value
        length_bits = self.binary_value(l, 64)
        self.put_binary_value(length_bits)

        if self.task_id:
            process_status[self.task_id]['status'] = "Embedding data into image"

        # Process in chunks for better performance and progress reporting
        chunk_size = 1024  # Process 1KB at a time
        for i in range(0, l, chunk_size):
            chunk = data[i:i+chunk_size]
            for byte in chunk:
                byte = byte if isinstance(byte, int) else ord(byte) # Compat py2/py3
                self.put_binary_value(self.byteValue(byte))

            if self.task_id:
                progress = min(100, int((i + len(chunk)) / l * 100))
                process_status[self.task_id]['progress'] = progress
                process_status[self.task_id]['status'] = f"Encoding: {progress}% complete"

        if self.task_id:
            process_status[self.task_id]['status'] = "Encoding complete"
            process_status[self.task_id]['progress'] = 100

        return self.image

    def decode_binary(self):
        try:
            if self.task_id:
                process_status[self.task_id]['status'] = "Reading data length"

            # Try to safely read the 64-bit length field
            try:
                # Read the first 64 bits which contain the length
                length_bits = ""
                for i in range(64):
                    try:
                        length_bits += self.read_bit()
                    except Exception as e:
                        # If we can't even read 64 bits, this isn't a valid stego image
                        raise ValueError("Failed to read data length. This doesn't appear to be a valid steganographic image.")

                # Convert to integer
                if not length_bits or len(length_bits) != 64:
                    raise ValueError(f"Invalid length field: expected 64 bits, got {len(length_bits)}")

                l = int(length_bits, 2)

                # Sanity check the length
                max_possible_size = (self.width * self.height * self.nbchannels) // 8
                # Check for reasonability - max 100MB or actual capacity, whichever is smaller
                max_reasonable_size = min(100*1024*1024, max_possible_size)

                if l <= 0 or l > max_reasonable_size:
                    raise ValueError(f"Invalid data length: {l} bytes. This may not be a valid steganographic image or the format has corrupted the data.")

            except ValueError as e:
                # Propagate ValueError as is
                raise e
            except Exception as e:
                # Convert other exceptions to a more informative message
                raise ValueError(f"Failed to decode length field: {str(e)}. This may not be a valid steganographic image.")

            if self.task_id:
                process_status[self.task_id]['status'] = f"Extracting {l} bytes of data"

            # Buffer to collect the decoded data
            output = bytearray()

            # Calculate chunk size for progress reporting
            chunk_size = max(1, l // 100)  # Target ~100 progress updates

            # Read the actual data bytes
            for i in range(l):
                try:
                    # Read 8 bits for one byte
                    byte_bits = ""
                    for j in range(8):
                        byte_bits += self.read_bit()

                    # Convert to integer and add to output
                    output.append(int(byte_bits, 2))

                    # Update progress
                    if self.task_id and (i % chunk_size == 0 or i == l-1):
                        progress = min(100, int((i + 1) / l * 100))
                        process_status[self.task_id]['progress'] = progress
                        process_status[self.task_id]['status'] = f"Decoding: {progress}% complete"

                except Exception as e:
                    # If we've read at least 80% of the data, return what we have
                    if i >= 0.8 * l:
                        logger.warning(f"Decoding truncated at {i}/{l} bytes. Returning partial data.")
                        if self.task_id:
                            process_status[self.task_id]['status'] = f"Decoding incomplete (got {i}/{l} bytes)"
                            process_status[self.task_id]['progress'] = 100
                        return bytes(output)
                    else:
                        # Otherwise, this is probably not a valid steganographic image
                        raise ValueError(f"Failed after reading {i}/{l} bytes: {str(e)}. The image may not contain valid steganographic data.")

            if self.task_id:
                process_status[self.task_id]['status'] = "Decoding complete"
                process_status[self.task_id]['progress'] = 100

            return bytes(output)

        except Exception as e:
            # Log and propagate any errors
            logger.error(f"Error in decode_binary: {str(e)}")
            if self.task_id:
                process_status[self.task_id]['status'] = f"Error: {str(e)}"
            raise

# Create a function to run decoding in a separate thread
def decode_file_task(image_path, task_id, result_filename):
    try:
        process_status[task_id] = {
            'status': 'Starting decoding process',
            'progress': 0,
            'filename': result_filename,
            'complete': False,
            'error': None
        }

        # Make sure the file exists
        if not os.path.exists(image_path):
            process_status[task_id]['error'] = "Image file not found"
            process_status[task_id]['complete'] = True
            return

        # Try to load the image
        try:
            encoded_image = cv2.imread(image_path)
            if encoded_image is None:
                process_status[task_id]['error'] = "Failed to load image. Ensure it's a valid PNG or JPG file."
                process_status[task_id]['complete'] = True
                return
        except Exception as e:
            process_status[task_id]['error'] = f"Failed to read image: {str(e)}"
            process_status[task_id]['complete'] = True
            return

        # Validate image dimensions
        if encoded_image.shape[0] < 4 or encoded_image.shape[1] < 4:
            process_status[task_id]['error'] = "Image is too small to contain any data"
            process_status[task_id]['complete'] = True
            return

        # Set up the steganography decoder
        steg = LSBSteg(encoded_image)
        steg.task_id = task_id

        process_status[task_id]['status'] = 'Reading hidden data from image'

        try:
            # Attempt to decode the data
            decoded_data = steg.decode_binary()

            # Verify we got some data
            if not decoded_data or len(decoded_data) == 0:
                process_status[task_id]['error'] = "No data was found in the image"
                process_status[task_id]['complete'] = True
                return

            # Save the decoded file
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], result_filename)

            with open(output_path, 'wb') as f:
                f.write(decoded_data)

            process_status[task_id]['status'] = 'Complete'
            process_status[task_id]['progress'] = 100
            process_status[task_id]['complete'] = True

            logger.debug(f"File decoded successfully to: {output_path}")

        except ValueError as e:
            # Handle validation errors (expected during decoding invalid images)
            process_status[task_id]['error'] = str(e)
            process_status[task_id]['complete'] = True
            logger.error(f"Decoding validation error: {str(e)}")

        except Exception as e:
            # Handle unexpected errors
            error_msg = str(e)
            if "No available slot" in error_msg:
                process_status[task_id]['error'] = "This image doesn't appear to contain valid steganographic data"
            else:
                process_status[task_id]['error'] = f"Error decoding data: {error_msg}"
            process_status[task_id]['complete'] = True
            logger.error(f"Decoding error: {error_msg}")
            logger.error(traceback.format_exc())

    except Exception as e:
        # Handle any errors in the task itself
        logger.error(f"Decoding task error: {str(e)}")
        logger.error(traceback.format_exc())
        process_status[task_id]['status'] = f'Error: {str(e)}'
        process_status[task_id]['error'] = str(e)
        process_status[task_id]['complete'] = True

# Create a function to run encoding in a separate thread
def encode_file_task(carrier_path, file_data, task_id, output_filename):
    try:
        process_status[task_id] = {
            'status': 'Starting encoding process',
            'progress': 0,
            'filename': output_filename,
            'complete': False,
            'error': None
        }

        # Check if the file exists
        if not os.path.exists(carrier_path):
            process_status[task_id]['error'] = "Carrier image file not found"
            process_status[task_id]['complete'] = True
            return

        # Load the carrier image
        try:
            carrier_image = cv2.imread(carrier_path)
            if carrier_image is None:
                process_status[task_id]['error'] = "Failed to load carrier image"
                process_status[task_id]['complete'] = True
                return
        except Exception as e:
            process_status[task_id]['error'] = f"Error loading carrier image: {str(e)}"
            process_status[task_id]['complete'] = True
            return

        # Validate data and image sizes
        data_size = len(file_data)
        available_bits = carrier_image.shape[0] * carrier_image.shape[1] * carrier_image.shape[2]
        required_bits = data_size * 8 + 64  # 64 bits for length

        if required_bits > available_bits:
            process_status[task_id]['error'] = f"File too large: needs {required_bits} bits, but only {available_bits} available in carrier image"
            process_status[task_id]['complete'] = True
            return

        # Set up the encoder
        steg = LSBSteg(carrier_image)
        steg.task_id = task_id

        # Encode the data
        try:
            process_status[task_id]['status'] = 'Embedding data into image'
            result_image = steg.encode_binary(file_data)

            # Save the output - Always as PNG to prevent data loss
            # Extract base name without extension and force PNG
            output_base = os.path.splitext(output_filename)[0]
            output_filename_png = f"{output_base}.png"
            output_path = os.path.join(app.config['UPLOAD_FOLDER'], output_filename_png)

            # Use PNG format with no compression for best results
            cv2.imwrite(output_path, result_image, [cv2.IMWRITE_PNG_COMPRESSION, 0])

            # Create a base64 image for preview
            with open(output_path, 'rb') as f:
                encoded_image = base64.b64encode(f.read()).decode('utf-8')

            # Update status
            process_status[task_id]['status'] = 'Complete'
            process_status[task_id]['progress'] = 100
            process_status[task_id]['complete'] = True
            process_status[task_id]['image'] = encoded_image
            process_status[task_id]['filename'] = output_filename_png  # Update with PNG filename

            logger.debug(f"File encoded successfully to: {output_path}")

        except Exception as e:
            process_status[task_id]['error'] = f"Error during encoding: {str(e)}"
            process_status[task_id]['complete'] = True
            logger.error(f"Encoding error: {str(e)}")
            logger.error(traceback.format_exc())

    except Exception as e:
        logger.error(f"Encoding task error: {str(e)}")
        logger.error(traceback.format_exc())
        process_status[task_id]['status'] = f'Error: {str(e)}'
        process_status[task_id]['error'] = str(e)
        process_status[task_id]['complete'] = True

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
        password = request.form.get('password', '')  # Password is now optional

        if not message:
            return jsonify({'error': 'No message provided'}), 400

        image = Image.open(image_file)
        # Pass password only if it's not empty
        stego_image = ImageMessageSteg.encode(image, message, password if password else None)

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
        password = request.form.get('password', '')  # Password is now optional

        stego_image = Image.open(image_file)
        # Pass password only if it's not empty
        message = ImageMessageSteg.decode(stego_image, password if password else None)
        return jsonify({'message': message})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# File in image steganography routes with progress tracking
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

        # Create a unique task ID for this encoding job
        task_id = f"encode_{timestamp}"
        output_filename = f"{timestamp}_encoded_{secure_filename(carrier_file.filename)}"

        # Start encoding in a separate thread
        encoding_thread = threading.Thread(
            target=encode_file_task,
            args=(carrier_path, file_data, task_id, output_filename)
        )
        encoding_thread.daemon = True
        encoding_thread.start()

        return jsonify({
            'success': True,
            'task_id': task_id,
            'status': 'Processing started',
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

        # Create a unique task ID and filename for this decoding job
        timestamp = int(time.time())
        task_id = f"decode_{timestamp}"
        output_filename = f'decoded_file_{timestamp}.bin'  # Adding .bin extension as a default

        # Start decoding in a separate thread
        decoding_thread = threading.Thread(
            target=decode_file_task,
            args=(image_path, task_id, output_filename)
        )
        decoding_thread.daemon = True
        decoding_thread.start()

        # Return immediately with the task ID for the client to poll
        return jsonify({
            'success': True,
            'task_id': task_id,
            'status': 'Processing started'
        })

    except Exception as e:
        logger.error(f"File decoding error: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/task_status/<task_id>')
def task_status(task_id):
    """Return the current status of a task"""
    if task_id not in process_status:
        return jsonify({'error': 'Task not found'}), 404

    status_info = process_status[task_id]

    # If the task is complete and there's no error, include download info
    if status_info.get('complete', False) and not status_info.get('error'):
        if task_id.startswith('decode_'):
            status_info['downloadPath'] = f'/download/{status_info["filename"]}'
        elif task_id.startswith('encode_') and 'image' in status_info:
            # For encode tasks, include the base64 image
            return jsonify({
                'success': True,
                'complete': True,
                'progress': 100,
                'status': 'Complete',
                'image': status_info['image'],
                'filename': status_info['filename']
            })

    return jsonify(status_info)

@app.route('/download/<filename>')
def download(filename):
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(file_path):
            logger.error(f"Download failed: File not found at {file_path}")
            return jsonify({'error': 'File not found'}), 404

        # Add better logging
        logger.debug(f"Attempting to download file: {file_path}")

        # Use a more robust approach to sending files
        try:
            return send_file(
                file_path,
                as_attachment=True,
                download_name=filename,  # Use download_name for newer Flask versions
                mimetype='application/octet-stream'
            )
        except AttributeError:
            # Fallback for older Flask versions
            return send_file(
                file_path,
                attachment_filename=filename,  # Use attachment_filename for older Flask versions
                as_attachment=True,
                mimetype='application/octet-stream'
            )
    except Exception as e:
        logger.error(f"Download error: {str(e)}")
        logger.error(traceback.format_exc())  # Add traceback for more detailed error info
        return jsonify({'error': f'Download failed: {str(e)}'}), 500

# Add cleanup function to periodically remove old files
def cleanup_old_files():
    """Remove files older than 24 hours from upload folder"""
    try:
        current_time = time.time()
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            # If file is older than 24 hours (86400 seconds)
            if os.path.isfile(file_path) and current_time - os.path.getmtime(file_path) > 86400:
                os.remove(file_path)
                logger.debug(f"Removed old file: {file_path}")
    except Exception as e:
        logger.error(f"Cleanup error: {str(e)}")

# Start a background thread to clean up old files every hour
def start_cleanup_thread():
    """Start the cleanup thread in the background"""
    while True:
        cleanup_old_files()
        # Sleep for 1 hour
        time.sleep(3600)

# Start the cleanup thread when the app starts
cleanup_thread = threading.Thread(target=start_cleanup_thread)
cleanup_thread.daemon = True
cleanup_thread.start()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5353)
