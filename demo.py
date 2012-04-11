from pypadbuster import *

from base64 import b64encode,b64decode
from Crypto.Cipher import AES

keysize    = 32
block_size = 16

def encrypt(iv_bytes, key, data):
  cipher = AES.new(key, AES.MODE_CBC, iv_bytes)
  return cipher.encrypt(pad_string_pkcs7(block_size, data))

def decrypt(key, ciphertext):
  # most padding oracles take the IV inline (ASP.NET etc), we do the same
  cipher = AES.new(key, AES.MODE_CBC, ciphertext[:block_size])
  data = verify_padding(cipher.decrypt(ciphertext[block_size:]))
  return data

def verify_padding(data):
  # check it's the right size
  if len(data) % block_size != 0:
    raise Exception((4,'Incorrect block length'))
  ret = []
  # split into original blocks
  blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
  for block in blocks:
    padding_length = ord(block[-1])
    # check that the padding is correct and within the block boundaries
    if not block.endswith(block[-1] * padding_length) or padding_length>block_size or padding_length < 1:
      return False
    else:
      ret.append( block[:-padding_length] )
  # if the padding oracle returns the decrypted block, we can derive the remaining
  # bytes of the XOR key by returning that here (the decrypted block will be matched
  # against the supplied IV):
  #return ''.join(ret)

  # if our padding oracle is a boolean "padding error"/"correct padding" oracle:
  return True

test_string = 'The quick brown fox jumped over the lazy dog and tried to span some blocks of ciphertext'

# random key + IV - hardcoded so we don't have to rely on os.random being present
key      = 'eb15c5814eae74213ccbb8a56c4f0a88ee73ba5904dea5ecec3f517bd7e06523'.decode('hex')
known_iv = '237731fc1e650c5f21d9af1c91539a50'.decode('hex')

bin_encrypted  = encrypt(known_iv, key, test_string)
padding_oracle = lambda iv,ciphertext: decrypt(key, iv+ciphertext)

bin_decrypted  = padding_oracle(known_iv, bin_encrypted)

if test_string != bin_decrypted and not bin_decrypted is True :
  raise Exception((5,'Self testing failed: "%s" != "%s"' % (test_string, bin_decrypted)))
encrypted = b64encode(known_iv + bin_encrypted)
print '\x1b[32;1m[*]\x1b[0m IV + encrypted version of "%s":\n%s' % (test_string, encrypted)

# The central thing is our padding oracle function:
#    padding_oracle(iv, ciphertext)
# that will return False if the input wasn't correctly padded
# (and a non-False value in all other cases)

(new_iv, new_ciphertext) = generate_ciphertext(block_size, test_string, padding_oracle)
print '\x1b[32;1m[*]\x1b[0m         iv:  %s' % new_iv.encode('hex')
print '\x1b[32;1m[*]\x1b[0m ciphertext:  %s' % new_ciphertext.encode('hex')

