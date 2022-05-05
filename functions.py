from bitstring import BitArray
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
import numpy as np
import base64
import pickle

# maps usernames to ENPs
authDB = {}


def register(username, password):
  if username in authDB:
    # TODO: raise a better error
    raise Exception("username already exists")

  hashedPass = getHash(password)
  hashedPassBits = BitArray(hex=hashedPass.hex()).bin[2:] # strip leading 0b

  negPass = getNegPass(hashedPassBits)
  enp = encryptAES(hashedPass, negPass) # probably replace this with python library encrypt func

  authDB[username] = enp


def login(username, password):
  if username not in authDB:
    raise Exception(f"no account for username {username} exists")

  enp = authDB[username]
  hashedPass = getHash(password)
  negPass = decryptAES(hashedPass, enp)
  hashedPassBits = BitArray(hex=hashedPass.hex()).bin[2:] # strip leading 0b
  
  if isSolution(hashedPassBits, negPass):
    return True

  else:
    raise Exception(f"incorrect password")


# ============ Internal Functions ==============
def isSolution(hashedPass, negPass):
  for entry in negPass:
    # if (len(entry) != len(negPass)):
    #   print("wrong length")
    #   return False
    # for i in range(len(entry)):
    #   if (entry[i] != '*' and entry[i] != hashedPass[i]):
      if matches(hashedPass, entry):
        return False
  return True

def matches(hashedPass, databaseEntry):
	if len(hashedPass) != len(databaseEntry):
		return False
	for i in range(len(hashedPass)):
		if databaseEntry[i] != "*" and databaseEntry[i] != hashedPass[i]:
			return False
	return True

def getHash(password):
  m = hashlib.sha256()
  # m = hashlib.sha1()  # 128 bits
  m.update(password.encode("utf-8"))

  return m.digest()


# key -- in bytes
# plaintext -- in bytes
def encryptAES(key, plaintext):
  # 128-bit encryption
  f = Fernet(base64.urlsafe_b64encode(key))
  ct = f.encrypt(pickle.dumps(plaintext))
  

  # TODO -- 256
  # iv = os.urandom(16)
  # cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) 
  # encryptor = cipher.encryptor()
  # ct = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()

  return ct

# key -- in bytes
def decryptAES(key, ct):
  # TODO -- 256
  # decryptor = cipher.decryptor()
  # return decryptor.udpate(ct) + decryptor.finalize()

  f = Fernet(base64.urlsafe_b64encode(key))
  return pickle.loads(f.decrypt(ct))

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
