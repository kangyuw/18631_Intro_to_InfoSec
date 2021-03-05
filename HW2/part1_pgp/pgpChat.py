#!/usr/bin/python3

#######################################
# 14-741 PGP Problem
# This problem simulates the encryption
# and decryption of PGP messages.
# Authors:
#   - @pranayga (Pandu)
#   - @abrar    (Arjun)
#######################################
import gnupg
import base64
import tempfile
from shutil import rmtree
import os
import json
from hkp4py import KeyServer

# File paths
TA_PRIV_KEY = "infosec_TA.priv"
SERVER_URL = "https://keys.mailvelope.com/"
TA_EMAIL = "ta-14741-18631@gmx.com"

KEY_SERVER = KeyServer("hkps://keys.mailvelope.com")

# Read Flag & Priv Pass
TA_PRIV_KEY_PASS = open("priv_pgp_pass",'r').read().strip()
flag = open("flag", "r").read().strip()


"""
    This function is reponsible for getting the correct 
    Public Key from the KeyServer and additing it to the 
    keyring.
    @param: `student_email` str email of the student
    @returns: Student Key's fingerprint
"""
def get_student_pub(student_email):
    keys = KEY_SERVER.search(student_email)
    print("{} keys found. Debug Info...".format(len(keys)))
    print("DEBUG Keys: ===========>")
    for key_itr in range(len(keys)):
        # Key Basic Information
        key = keys[key_itr]
        print("key Index:\t{}".format(key_itr))
        print("Key Algorithm:\t{}".format(key.algo))
        print("Key fpr:\t{}".format(key.keyid))
        print("Expired?\t{}".format('yes' if key.expired else 'no'))
        print("Revoked?\t{}".format('yes' if key.revoked else 'no'))
        print("Date Created:\t{}".format(key.creation_date))
        print("Date Expired:\t{}".format(key.expiration_date))
        print(key.key)
        print("---------+++++---------")
    target_key_id = int(input("Enter the keypair to use (key Index above): "))
    student_pub_add = gpg.import_keys(keys[target_key_id].key)  #<-- Adding the key to the ring
    print("Student Key add: {}".format(student_pub_add.results))
    print("=====================================")
    return keys[target_key_id].keyid

if __name__=="__main__":

    print("""""")
    try:
        # setting up Keybase
        if not os.path.exists('.pgp_temp'):
            os.makedirs('.pgp_temp')
        GNU_HOMEDIR = tempfile.mkdtemp(dir='.pgp_temp')
        gpg = gnupg.GPG(gnupghome=GNU_HOMEDIR)
        # Add the priv key
        priv_key_data = open(TA_PRIV_KEY).read()
        TA_priv_add = gpg.import_keys(priv_key_data)
        
        # Echo Server's public Key Email
        print("Starting Phase I....")
        print("Find Problem's Public Key at {},\nEmail: {}".format(SERVER_URL,TA_EMAIL))
        print("For Phase I, you will have to generate a gpg RSA key and share it on the https://keys.mailvelope.com similar to how TA's key is hosted. This program will then use that publically shared PUBLIC Key to verify and communicate with you.")
        
        # Get student's email & query https://keys.mailvelope.com/manage.html
        print("Starting Phase II....")
        student_email = input("Give me your email ID: ")
        print(student_email)
        student_fingerprint = get_student_pub(student_email)

        # Get Signed Email to prove he's got the priv key
        print("Wait a minute, can you prove that you own this key?")
        base64_signed_email = input("Hint: --clear-sign might be helpful.\nbase64(signed(<email>)): ")
        signed_email = base64.b64decode(base64_signed_email,validate=True)
        print("Decoded Signature message:\n{}".format(signed_email.decode('utf-8')))
        verified_obj = gpg.verify(signed_email)
        if not verified_obj or verified_obj.fingerprint!=student_fingerprint:
            print("Unable to verify Signature. Are you Sure this is your key?")
            raise Exception("Invalid Signature.")
        print("Signature from {}, Fingerprint:{} verified.\n".format(verified_obj.username, 
                                                                verified_obj.fingerprint))

        # Parse incoming Encrypted message
        print("""Hint: Target JSON to send: {"command":"get_flag"}""")
        base64_enc_req = input("Give me base64(enc(target_json)): ")
        enc_PGP_control_message = base64.b64decode(base64_enc_req,validate=True)
        dec_control_message = gpg.decrypt(enc_PGP_control_message, passphrase=TA_PRIV_KEY_PASS)
        print("Incoming PGP control Message:\n{}".format(enc_PGP_control_message.decode('utf-8')))
        print("Decrypted Message: {}".format(dec_control_message))

        # Encypt flag with the public key
        command_json = json.loads(str(dec_control_message))
        if("get_flag" in command_json["command"]): #<-- using `in` to allow some formatting errors
            pgp_enc_flag = gpg.encrypt(flag,student_email, always_trust=True)
            print("Here's your personal flag: \n{}\n".format(pgp_enc_flag))
        else:
            print("Invalid Control command")

    except Exception as e:
        print("Program possibly failed with ERROR: {}".format(str(e)))
        raise
    
    finally:
        rmtree(GNU_HOMEDIR)
