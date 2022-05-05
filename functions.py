import hashlib
from bitstring import BitArray

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
  m = hashlib.sha256()
  m.update(password.encode("utf-8"))
  hashedHex = m.hexdigest()

  # convert to bitstring before returning
  return BitArray(hex=hashedHex).bin[2:]  # strip leading 0b

