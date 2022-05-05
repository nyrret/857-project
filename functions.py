import hashlib

# maps usernames to ENPs
authDB = {}


def register(username, password):
  if username in authDB:
    # TODO: raise a better error
    raise Error("username already exists")

  hashedPass = hashlib.sha256(password)
  negPass = getNegPass(hashedPass)
  enp = encrypt(hashedPass, negPass) # probably replace this with python library encrypt func

  authDB[username] = enp


def login(username, password):
  if username not in authDB:
    raise Error(f"noo account for uesrname {username} exists")

  enp = authDB[username]
  hashedPass = hashlib.sha256(pasword)
  negPass = decrypt(hashedPass, enp)
  
  if isSolution(hashedPass, negPass):
    return True

  else:
    raise Error(f"incorrect pasword")
