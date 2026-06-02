import os 
import json
import uuid
from cryptography.fernet import Fernet
from auth import derive_key

VAULT_FILE = "vault.json"

def load_vault(passwd):
    key = derive_key(passwd)
    fer = Fernet(key)

    try:
        with open(VAULT_FILE, "rb") as f:
            contents = f.read()
            decrepted = fer.decrypt(contents)
            json_strings = decrepted.decode()
            entries = json.loads(json_strings)
            return entries
    except FileNotFoundError:
        return []

def save_vault(passwd, entries):
    key = derive_key(passwd)
    fer = Fernet(key)

    json_strings = json.dumps(entries)
    encoded = json_strings.encode()
    encrypted = fer.encrypt(encoded)

    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)
    

def add_entry(passwd, service, username, password):

    entries = load_vault(passwd)
    entries.append({"id":str(uuid.uuid4()),"service":service, "username": username, "password":password})
    save_vault(passwd, entries)


def delete_entry(passwd, entry_id):

    if not isinstance(entry_id, str) or not entry_id.strip():
        raise TypeError(f"Entry id must be a non_empty string, got {type(entry_id).__name__}.")

    entries = load_vault(passwd)

    updated = [entry for entry in entries if entry["id"] != entry_id]

    save_vault(passwd, updated)
    
def get_all_entries(passwd):
    return load_vault(passwd)
