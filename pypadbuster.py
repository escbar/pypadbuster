#!/bin/env python

def pad_string_pkcs7(block_size, unpadded):
  # PKCS7 padding as described in RFC 5652
  blocks=[]
  for bptr in xrange(0, len(unpadded)+1 -len(unpadded) % block_size, block_size-1):
    this_block   = unpadded[bptr : bptr+block_size-1]
    padding_size = block_size - len(this_block)
    blocks.append(this_block  +  padding_size * chr(padding_size))
  return ''.join(blocks)

def breakablock(block_size, enc, padding_oracle):
  translation_table = padding = ''
  if not len(enc) % block_size ==0: raise Exception((1,'Incorrect wrong size %d' % len(enc)))
  for i in range(0, block_size):
    # This would be a good place to add parallelization since we need the IV
    # of the block before us to attempt to break a block.

    # we control the IV supplied. (it is not MAC'ed, so we can change it)
    for c in range(0,256):
      # try to bruteforce the value for the padding: 0x01, 0x0202, 0x030303, etc
      padding = chr(i+1)*(i)
      new_iv =  (block_size-i-1)*'\x00' + chr(c)
      for lc in range(0,len(padding)):
	new_iv += xorstring(translation_table[lc], padding[lc])
      decrypt_result = padding_oracle(new_iv, enc)
      if not decrypt_result is False:
	if decrypt_result is True:
	  print '\x1b[35;1m[*]\x1b[0m IV byte %2d: Padding "%s" [%d] is valid with IV %s' % (i, (chr(i+1)*(i+1)).encode("hex"),len(padding)+1, new_iv.encode("hex"))
	  translation_table = chr((c ^ (i+1))&255) + translation_table
	else:
	  if len(decrypt_result) > block_size:
	    raise Exception((4,"We thought we had a leaked block, but we didn't decode it correctly: %s: %s" % (decrypt_result.encode('hex'), decrypt_result)))
	  padding_chr = abs( len(decrypt_result) - block_size)
	  leaked_plaintext  = decrypt_result + chr(padding_chr) * padding_chr
	  translation_table = xorstring(new_iv, leaked_plaintext)
	  print '\x1b[35;1m[*]\x1b[0m IV byte %2d: Jackpot! %s leaked the block! XOR key: %s' % (i, new_iv.encode('hex'), translation_table.encode('hex'))
	break
    else:
      raise Exception((2,"Unable to find valid padding despite exhaustive search - is our oracle function lying? Did you specify the right block length? (This should never happen)"))
    if len(translation_table) == block_size:
      break
  return translation_table

def xorstring(key,data):
  build = "";
  for i in range(0,len(data)):
    build += chr( ord(key[i%len(key)])  ^ ord(data[i]))
  return build

def generate_ciphertext(block_size, wantedstr, padding_oracle):
  # TODO we can calculate the block size by taking the first 32 bytes of a valid
  # ciphertext and checking:
  # - if len % 16 is 8, the block size is 8 bytes
  # - if len % 16 is 0, replace byte 8 with a new byte. if the result is still
  # valid, the block size is 16 bytes
  wanted = pad_string_pkcs7(block_size, wantedstr)
  print '\x1b[33;1m[*]\x1b[0m Going to produce %d blocks: %s' % (len(wanted) / block_size, repr(wanted))
  ciphertext = ''
  iv         = '\x00' * block_size
  for bptr in range(len(wanted) / block_size -1, -1, -1):
    block      = xorstring('\x00'*block_size, iv)
    xor_key    = breakablock(block_size, block, padding_oracle)
    ciphertext = block + ciphertext
    iv         = xorstring( wanted[bptr*block_size:bptr*block_size+block_size],
			    xor_key)

  if padding_oracle( iv,  ciphertext) == False:
    raise Exception((3,"Unable to generate ciphertext, our best guess was: %s : %s" % (iv.encode('hex'),ciphertext.encode('hex'))))

  return (iv, ciphertext)

if __name__ == '__main__':
  import demo
