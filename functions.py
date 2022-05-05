from bitstring import BitArray
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import numpy as np

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
    raise Error(f"noo account for username {username} exists")

  enp = authDB[username]
  hashedPass = _getHash(password)
  negPass = _decrypt(hashedPass, enp)
  
  if _isSolution(hashedPass, negPass):
    return True

  else:
    raise Error(f"incorrect password")


# ============ Internal Functions ==============
def _isSolution(hashedPass, negPass):
    for entry in negPass:
        if (len(entry) != len(negPass)):
            return False
        for i in range(len(entry)):
             if (entry[i] != '*' and entry[i] == hashedPass[i]):
                 return False
    return True

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

def getNegPass(hashedPass):
	permutation = np.random.permutation(len(hashedPass))
	permutedPass = permute(hashedPass, permutation)
	negativeDB=[]
	for i in range(len(permutedPass)):
		negativeDB.append(inversePermute(permutedPass[:i]+opposite(permutedPass[i]) + "*"*(len(permutedPass)-i-1), permutation))
	return negativeDB

def opposite(bit):
	if bit=="1":
		return "0"
	else: return "1"

def permute(bitString, permutation):
	permutedString=""
	for i in range(len(permutation)):
		permutedString += bitString[permutation[i]]
	return permutedString

def inversePermute(permutedString, permutation):
	bitString=""
	for i in range(len(permutedString)):
		bitString += permutedString[np.nonzero(permutation==i)[0][0]]
	return bitString
