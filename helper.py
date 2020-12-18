from hashlib import sha256

#print(sha256(bytes.fromhex('03f6a8f0d8542c31f230a3f451a218facca8542651c9e65be7e153cf26974807ce')).hexdigest())

message = sha256(bytes.fromhex('0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352')).hexdigest()


import hashlib

data=bytes.fromhex(message)

print(hashlib.new('ripemd160', data).hexdigest())

  
  
