import hmac
import hashlib
from binascii import unhexlify, hexlify
from math import ceil, floor, log
import time
from os import urandom

import sys
message="AAAAAAAAAABBBBBBBBBCCCCCCCCC"

def random_key(x, n=32): 
    key = hexlify(urandom(n)) #returns a 256 bit hex encoded (64 bytes) random number
    print "\nPrivate key value " , x , " : ", key
    return key

def sha256(message):
    return hashlib.sha256(message).hexdigest()

def sha256b(message):
    return hashlib.sha256(message).digest()

def random_wkey(w=8, verbose=0):      #create random W-OTS keypair

    priv = []
    pub = []
    print "=============== Public - Private key pair generation ================"
    raw_input("Press enter to continue....")    
    
    for x in range(256/w):
        a = random_key(x)
        priv.append(a)
        print "\n\t",2**w,"Hashing (SHA-256) iterations ",
        for y in range(2**w):              
            a = sha256(a)
            print ">",
        pub.append(a)
        print "\n\nPublic key value " , x , " : ", a 
    
    raw_input("Press enter to continue....")    
    return priv, pub 

def sign_wkey(priv, message):      
    print "\n=============== Signature (privatekey, message)==============="
    raw_input("Press enter to continue....")  
    signature = []
    bin_msg = unhexlify(sha256(message))
    print "\n\t",bin_msg

    for y in range(len(priv)):
        s = priv[y]   
        messageHashPieceValue = ord(bin_msg[y:y+1])
        print "\n\t\t 256 -",messageHashPieceValue,"=",256 - messageHashPieceValue,"Hashing (SHA-256) iterations over PRIVATE KEY piece",y 
        for x in range(256 - messageHashPieceValue):
            print ">",
            s = sha256(s)
        signature.append(s)
    return signature

def verify_wkey(signature, message, pub):
    print "\n=============== Verify (signature, message, publickey) ==============="
    raw_input("Press enter to continue....")  

    verify = []
    bin_msg = unhexlify(sha256(message))
    print "\n\t",bin_msg
    
    for x in range(len(signature)):
        a = signature[x]
        
        messageHashPieceValue = ord(bin_msg[x:x+1])
        print "\n\t\t",messageHashPieceValue,"Hashing (SHA-256) iterations over SIGNATURE piece",x                                             
        for z in range(messageHashPieceValue):
                a=sha256(a)
                print ">",
        # a = sha256(a + ".")                                # is the final hash, separate so can be changed..
        verify.append(a)
  
    if pub != verify:
        return False

    return True


priv, pub = random_wkey()

print "\n=============== Private key (keep secret) ==============="
print "Priv[0]: ",priv[0]
print "Priv[1]: ",priv[1]
print "Priv[2]: ",priv[2]
print "Priv[3]: ",priv[3]
print "Priv[4]: ",priv[4]
print "Priv[5]: ",priv[5]
print "..."
print "Priv[31]: ",priv[31]


print "\n=============== Public key (show everyone) ==============="
print "Pub[0]: ",pub[0]
print "Pub[1]: ",pub[1]
print "Pub[2]: ",pub[2]
print "Pub[3]: ",pub[3]
print "Pub[4]: ",pub[4]
print "Pub[5]: ",pub[5]
print "..."
print "Pub[31]: ",pub[31]

print "\n=============== Message to sign ==============="
print "Message:\t",message
print "SHA-256:\t",sha256(message)

sign = sign_wkey(priv,message)

print "\n=============== Signature ==============="
print "Sign[0]:\t",sign[0]
print "Sign[1]:\t",sign[1]
print "Sign[2]:\t",sign[2]
print "Sign[3]:\t",sign[3]
print "..."
print "Sign[31]: ",sign[31]

result = verify_wkey(sign,message,pub)


print "\n=============== Verification result ==============="
print "\nThe signature test is ....... ",
raw_input("?????")  
print "\n",result