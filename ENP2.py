from bitstring import BitArray
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet, InvalidToken
import numpy as np
import base64
import pickle
from numpy.random import default_rng

# maps usernames to ENPs
authDB = {}

rng = default_rng()

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
  try:
    negPass = decryptAES(hashedPass, enp)
  except InvalidToken:
    raise Exception("incorrect password")

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
  print(permutedPass)
  negativeDB=[]
  for i in range(len(permutedPass)-1, 1, -1): #One of these steps works if the first two bits agree
    j, k = rng.integers(low=0, high=i, size=2)
    while (j == k):
      j, k = rng.integers(low=0, high=i, size=2)
    if(j < k):
      toAdd = "*" * j + permutedPass[j] + "*" * (k-j-1) + permutedPass[k] + "*" * (i-k-1) + opposite(permutedPass[i]) + "*" * (len(permutedPass)-i-1)
    if(k < j):
      toAdd = "*" * k + permutedPass[k] + "*" * (j-k-1) + permutedPass[j] + "*" * (i-j-1) + opposite(permutedPass[i]) + "*" * (len(permutedPass)-i-1)
    negativeDB.append(inversePermute(toAdd, permutation))

  j = rng.integers(low = 2, high = len(permutedPass)) #If the second bit disagrees but the first bit agrees
  StartOfToAdd= permutedPass[0] + opposite(permutedPass[1]) + "*" * (j-2)
  negativeDB.append(inversePermute(StartOfToAdd + str(0) + "*" * (len(permutedPass)-j-1), permutation))
  negativeDB.append(inversePermute(StartOfToAdd + str(1) + "*" * (len(permutedPass)-j-1), permutation))

  j, k = rng.integers(low = 1, high = len(permutedPass), size = 2) # if the first bit disagrees and the jth bit is 0
  while(j == k):
    j, k = rng.integers(low = 1, high = len(permutedPass), size = 2)
  if (j < k):
    StartOfToAdd = opposite(permutedPass[0]) + "*" * (j-1) + str(0) + "*" * (k-j-1)
    negativeDB.append(inversePermute(StartOfToAdd + str(0) + "*" * (len(permutedPass)-k-1), permutation))
    negativeDB.append(inversePermute(StartOfToAdd + str(1) + "*" * (len(permutedPass)-k-1), permutation))
  if(k < j):
    StartOfToAdd = opposite(permutedPass[0]) + "*" * (k-1)
    negativeDB.append(inversePermute(StartOfToAdd + str(0) + "*" * (j-k-1) + str(0) + "*" * (len(permutedPass)-j-1), permutation))
    negativeDB.append(inversePermute(StartOfToAdd + str(1) + "*" * (j-k-1) + str(0) +  "*" * (len(permutedPass)-j-1), permutation))

  k = rng.integers(low = 1, high = len(permutedPass)) # if the first bit disagrees and the jth bit is 1
  while (j == k):
    k = rng.integers(low = 1, high = len(permutedPass))
  if (j < k):
    StartOfToAdd = opposite(permutedPass[0]) + "*" * (j-1) + str(1) + "*" * (k-j-1)
    negativeDB.append(inversePermute(StartOfToAdd + str(0) + "*" * (len(permutedPass)-k-1), permutation))
    negativeDB.append(inversePermute(StartOfToAdd + str(1) + "*" * (len(permutedPass)-k-1), permutation))
  if(k < j):
    StartOfToAdd = opposite(permutedPass[0]) + "*" * (k-1)
    negativeDB.append(inversePermute(StartOfToAdd + str(0) + "*" * (j-k-1) + str(1) + "*" * (len(permutedPass)-j-1), permutation))
    negativeDB.append(inversePermute(StartOfToAdd + str(1) + "*" * (j-k-1) + str(1) + "*" * (len(permutedPass)-j-1), permutation))
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
  return permutedString
	# bitString=""
	# for i in range(len(permutedString)):
	# 	bitString += permutedString[np.nonzero(permutation==i)[0][0]]
	# return bitString


db = getNegPass("1100101100001")
print(db)