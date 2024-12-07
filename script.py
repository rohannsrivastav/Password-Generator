
import time

from hashlib import sha256

if __name__ == '__main__':
  passLen = input("Length Required: \n")
  passLen = int(passLen)
  epoch_time = int(time.time())
  phrase = "The Tomb of Saint Nicholas"
  
  input_ = phrase + str(epoch_time)
  
  hash_digest = sha256(input_.encode('utf-8')).hexdigest()
  
  print(hash_digest[0:passLen])
