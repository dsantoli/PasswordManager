from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

def load_key():
    """ Load the encryption key from a file or environment variable """
    return open("../secret_key/path_to_key.key", "rb").read()

cipher_suite = Fernet(load_key())

def encrypt_password(plain_text_password):
    """Encrypt a plaintext password."""
    return cipher_suite.encrypt(plain_text_password.encode()).decode('utf-8')

def decrypt_password(encrypted_password):
    """Decrypt an encrypted password."""
    return cipher_suite.decrypt(encrypted_password.encode()).decode('utf-8')

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 requires a 32-byte key
        salt=salt,
        iterations=100000,  
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Encode the password to bytes if not already
    return key

def encrypt_data(key: bytes, data: str) -> str:
    iv = os.urandom(16)  # AES block size for CFB mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return base64.urlsafe_b64encode(iv + encrypted_data).decode()

def decrypt_data(key: bytes, token: str) -> str:
    # Decode the base64-encoded encrypted token
    token_bytes = base64.urlsafe_b64decode(token)
    
    # Extract the initialization vector (IV) and the encrypted data
    iv = token_bytes[:16]
    encrypted_data = token_bytes[16:]
    
    # Create a cipher object and decryptor instance
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the data and finalize the decryption process
    decrypted_bytes = decryptor.update(encrypted_data) + decryptor.finalize()
    
    # Decode the decrypted bytes into a UTF-8 string
    decrypted_text = decrypted_bytes.decode('utf-8')
    
    return decrypted_text