from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Function to pad data to AES block size (16 bytes)
def pad(data):
    block_size = AES.block_size
    padding = block_size - len(data) % block_size
    return data + bytes([padding]) * padding

# Function to unpad data
def unpad(data):
    return data[:-data[-1]]

# Generate a random 256-bit key and IV
key = get_random_bytes(32)  # 256 bits
iv = get_random_bytes(AES.block_size)  # 16 bytes

# Sample plaintext
plaintext = b"Hello, this is a secret message!"

# Encrypt
cipher = AES.new(key, AES.MODE_CBC, iv)
padded_plaintext = pad(plaintext)
ciphertext = cipher.encrypt(padded_plaintext)
# Encode to base64 for easy display/storage
encoded_ciphertext = base64.b64encode(iv + ciphertext).decode('utf-8')
print("Encrypted (base64):", encoded_ciphertext)

# Decrypt
decoded_data = base64.b64decode(encoded_ciphertext)
iv_from_data = decoded_data[:AES.block_size]
ciphertext_from_data = decoded_data[AES.block_size:]
cipher = AES.new(key, AES.MODE_CBC, iv_from_data)
decrypted_padded = cipher.decrypt(ciphertext_from_data)
decrypted_plaintext = unpad(decrypted_padded)
print("Decrypted:", decrypted_plaintext.decode('utf-8'))
