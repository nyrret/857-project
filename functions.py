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

  enp = authDB[username]
  hashedPass = getHash(pasword)
  negPass = decrypt(hashedPass, enp)
  
  if isSolution(hashedPass, negPass):
    return True

  else:
    raise Error(f"incorrect pasword")

def isSolution(hashedPass, negPass):
    for entry in negPass:
        if (len(entry) != len(negPass)):
            return False
        for i in range(len(entry)):
             if (entry[i] != '*' and entry[i] == hashedPass[i]):
                 return False
    return True
