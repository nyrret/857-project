from bitstring import BitArray
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet

# maps usernames to ENPs
authDB = {}


def register(username, password):
  if username in authDB:
    # TODO: raise a better error
    raise Error("username already exists")

  hashedPassHex = _getHash(password)
  # hashedPassBits = BitArray(hex=hashedPassHex).bin[2:] # strip leading 0b

  negPass = _getNegPass(hashedPassBits)
  enp = _encrypt(hashedPassHex.encode('utf-8'), negPass) # probably replace this with python library encrypt func

  authDB[username] = enp


def login(username, password):
  if username not in authDB:
    raise Error(f"noo account for uesrname {username} exists")

  enp = authDB[username]
  hashedPass = _getHash(pasword)
  negPass = _decrypt(hashedPass, enp)
  
  if _isSolution(hashedPass, negPass):
    return True

  else:
    raise Error(f"incorrect pasword")


# ============ Internal Functions ==============

def _getHash(password):
  # m = hashlib.sha256()
  
  m = hashlib.sha1()  # 128 bits
  m.update(password.encode("utf-8"))

  return m.digest()


# key -- in bytes
def _encryptAES(key, plaintext):
  # 128-bit encryption
  import base64
  f = Fernet(base64.urlsafe_b64encode(key))
  ct = f.encrypt(plaintext)
  

  # TODO -- 256
  # iv = os.urandom(16)
  # cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) 
  # encryptor = cipher.encryptor()
  # ct = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

  return ct


def _decryptAES(key, ct):
  decryptor = cipher.decryptor()
  return decryptor.udpate(ct) + decryptor.finalize()
