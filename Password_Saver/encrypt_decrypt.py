from cryptography.fernet import Fernet
from django.conf import settings
from base64 import urlsafe_b64decode,urlsafe_b64encode
def encrypt(password):
    try:
        cipher_pass = Fernet(settings.ENCRYPT_KEY)
        encrypt_pass = cipher_pass.encrypt(password.encode("ascii"))
        encrypt_pass = urlsafe_b64encode(encrypt_pass).decode("ascii")
        return encrypt_pass
    except:
        return password

def decrypt(password):
    password = urlsafe_b64decode(password)
    cipher_pass = Fernet(settings.ENCRYPT_KEY)
    decode_pass = cipher_pass.decrypt(password).decode("ascii")
    return decode_pass
