from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import ciphers, hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import base64

# encrypt with shared key
# USE KEY TO ENCRYPT THE DATA FIRST
# GCM Mode, we also need an IV
def encrypt_with_shared_key(key,iv,message,auth):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(auth)
    cipher_text = encryptor.update(message) + encryptor.finalize()
    tag = encryptor.tag
    return cipher_text,tag

# Same as above method but decrypts
def decrypt_with_shared_key(key,iv,tag,cipher_text,auth):
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
    decryptor.authenticate_additional_data(auth)
    result = decryptor.update(cipher_text) + decryptor.finalize()
    return result

def encryptTagIvAuth(tag,iv,auth, public_key):
    # ENCRYPT THE TAG USING PUBLIC KEY
    ctag = public_key.encrypt(
        tag,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))

    # ENCRYPT IV USING PUBLIC KEY
    civ = public_key.encrypt(
        iv,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))


    # ENCRYPT AUTH DATA USING PUBLIC KEY
    cauth = public_key.encrypt(
        auth,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))
    # KEY: 16 BYTES
    # SIGNATURE: HASHED 32 BYTES
    # TAG: 16 BYTES

    # SERIALIZE THE DATA AND PUT ALL TO FILE
    return json.dumps([ctag, civ, cauth])

def decryptTagIvAuth(encrypted_tag_iv_auth, private_key):
    ctag = encrypted_tag_iv_auth[0]
    civ = encrypted_tag_iv_auth[1]
    cauth = encrypted_tag_iv_auth[2]

    tag = private_key.decrypt(
            ctag,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    iv = private_key.decrypt(
            civ,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    auth = private_key.decrypt(
            cauth,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return (tag,iv,auth)

# LOAD THE PRIVATE KEY
def load_private_key(filepath):
    with open(filepath, "rb") as key_file:
        if filepath.endswith('.der'):
            private_key = serialization.load_der_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
            return private_key
        elif filepath.endswith('.pem'):
            private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend())
            return private_key

# LOAD THE PUBLIC KEY
def load_public_key(filepath):
    with open(filepath, "rb") as key_file:
        if filepath.endswith('.der'):
            public_key = serialization.load_der_public_key(
                key_file.read(),
                backend=default_backend())
            return public_key
        elif filepath.endswith('.pem'):
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())
            return public_key

# encrypt with shared key
# decodes the input key to base 64 and obtains the first 128 bits and encrypts the input message with AES and CTR mode
def encrypt_CTR_with_shared_key(key,message,nonce):
    decoded_key = base64.b64decode(key)
    aes_key = decoded_key[0:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(message) + encryptor.finalize()
    return cipher_text

# Same as above method but decrypts
def decrypt_CTR_with_shared_key(key,cipher_text,nonce):
    decoded_key = base64.b64decode(key)
    aes_key = decoded_key[0:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    message = decryptor.update(cipher_text) + decryptor.finalize()
    return message

# transforms the key to a 128 bit key and computes hmac and returns the hmac
def get_hmac_from_shared_key(key,msg):
    decoded_key = base64.b64decode(key)
    hmac_key = decoded_key[0:16]
    h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    h.update(msg)
    h_mac = h.finalize()
    return h_mac

#verifies the hmac
def verify_hmac_with_shared_key(key,msg,h_mac):
    try :
        decoded_key = base64.b64decode(key)
        hmac_key = decoded_key[0:16]
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(msg)
        h.verify(h_mac)
        return True
    except:
        return False
