import os 
import bcrypt
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes



HASH_FILE = "master.hash"
SALT_FILE = "salt.bin"

def setup_masterpasswd(passwd):
    if os.path.exists(HASH_FILE) and os.path.exists(SALT_FILE):
        raise RuntimeError("Vault already exits.")
    if len(passwd) < 8:
        raise Exception("Password not strong!") 

    hashed = bcrypt.hashpw(passwd.encode(), bcrypt.gensalt())
    with open(HASH_FILE, "wb") as f:
        f.write(hashed)
 

    salt = os.urandom(16)
    with open(SALT_FILE, "wb") as f:
        f.write(salt)


def verify_masterpasswd(passwd):
    try:
        with open(HASH_FILE, "rb") as f:
            stored_hash = f.read()
    except FileNotFoundError:
        return False
    
    return bcrypt.checkpw(passwd.encode(), stored_hash)


def derive_key(passwd):
    try:
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
    except FileNotFoundError:
        raise FileNotFoundError("Salt file missing, vault may be corrupted.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,   
    )
    return base64.urlsafe_b64encode(kdf.derive(passwd.encode()))

def is_first_run():
    return not os.path.exists(HASH_FILE) and not os.path.exists(SALT_FILE)