import hashlib
from bitstring import BitArray
import numpy as np

# maps usernames to ENPs
authDB = {}


def register(username, password):
  if username in authDB:
    # TODO: raise a better error
    raise Error("username already exists")

  hashedPass = _getHash(password)
  negPass = _getNegPass(hashedPass)
  enp = _encrypt(hashedPass, negPass) # probably replace this with python library encrypt func

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
  m = hashlib.sha256()
  m.update(password.encode("utf-8"))
  hashedHex = m.hexdigest()

  # convert to bitstring before returning
  return BitArray(hex=hashedHex).bin[2:]  # strip leading 0b


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