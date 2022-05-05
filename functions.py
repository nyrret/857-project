# maps usernames to ENPs
authDB = {}


def register(username, password):
  if username in authDB:
    # TODO: raise a better error
    raise Error("username already exists")

  hashedPass = getHash(password)
  negPass = getNegPass(hashedPass)
  enp = encrypt(hashedPass, negPass) # probably replace this with python library encrypt func

  authDB[username] = enp


def login(username, password):
  if username not in authDB:
    raise Error(f"noo account for uesrname {username} exists")


