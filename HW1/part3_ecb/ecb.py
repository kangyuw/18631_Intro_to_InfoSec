#!/usr/bin/python3 -u
import os
import json
import sys
import time

from Crypto.Cipher import AES

cookiefile = open("cookie", "r").read().strip()
flag = open("flag", "r").read().strip()
key = open("key", "r").read().strip()

welcome = """
Welcome to ECB Secure Encryption Service version 1.36
"""
def encrypt(m):
  cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
  return cipher.encrypt(m).hex()

def decrypt(m):
  cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
  return (cipher.decrypt(bytes.fromhex(m))).decode('utf-8')
  

# flush output immediately
print (welcome)
print (len(cookiefile))
print ("Here is an admin cookie: " + encrypt(cookiefile))
print ("But here is yours: " + encrypt("I am not an administrator. This cookie expires 2021-05-01......."))

# Get their cookie
print ("What is your cookie?")
cookie2 = sys.stdin.readline()
# decrypt, but remove the trailing newline first
cookie2decoded = decrypt(cookie2[:-1])
print (cookie2decoded)

if cookie2decoded.startswith('I am yes an admin'):
   exptime=time.strptime(cookie2decoded[47:57],'%Y-%m-%d')
   if exptime > time.localtime():
      print ("Cookie is not expired")
      print ("The flag is: " + flag)
   else:
      print ("Cookie is expired")
else:
   print ("No flag for you!")
