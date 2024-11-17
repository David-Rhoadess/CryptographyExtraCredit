#Based on Natasha.py which was given in the assignment

from Crypto.Hash import SHA
from Crypto.Util.strxor import strxor 
from natasha import ENC, DEC

class TypeError(Exception):
    def __init__(self, message):
        self.message = message

class LengthError(Exception):
    def __init__(self, message):
        self.message = message

def RF(L, R, K):
    sha = SHA.new()
    sha.update(K+R+K)
    return strxor(L, sha.digest()), R

block1 = bytes.fromhex('ae055b48d8fa60bc337ff846ee88fe33c7e026a5ea54dbb59814c68265540cef1c183ef746553686')
block2 = bytes.fromhex('8c4febe7e2f0a6d43110d37576535b8518eaa4b7ce3ac3722816062755aa8b5ed82eadf76e8af6f5')

def DEC2(Y, K):

    #raise TypeError("balls")
    if type(K) != bytes:
        raise TypeError("Key must be of type bytes!")
        return
    
    if len(K) != 3:
        raise LengthError("Key length must be of length 3 bytes!")
        return
    
    if type(Y) != bytes:
        raise TypeError("Input block must be of type bytes!")
        return
    
    if len(Y) != 40:
        raise LengthError("Block length must be of length 40 bytes!")
        return    
    
    K0 = K[0:1]
    K1 = K[1:2]
    K2 = K[2:3]
    #K3 = K[3:4]
    #K4 = K[4:5]
    #K5 = K[5:6]

    L, R = Y[0:20], Y[20:40]
    #R, L = RF(L, R, K5)
    #R, L = RF(L, R, K4)
    #R, L = RF(L, R, K3)
    R, L = RF(L, R, K2)
    R, L = RF(L, R, K1)
    R, L = RF(L, R, K0)
    return R

block1plain = 'Meet_NataSHA_which_is_not_a_SHA_although'
block1plain = block1plain.encode('utf-8')

def ENC2(X, K):

    if type(K) != bytes:
        raise TypeError("Key must be of type bytes!")
        return
    
    if len(K) != 2:
        raise LengthError("Key length must be of length 2 bytes!")
        return
    
    if type(X) != bytes:
        raise TypeError("Input block must be of type bytes!")
        return
    
    if len(X) != 40:
        raise LengthError("Block length must be of length 40 bytes!")
        return    
    
    K0 = K[0:1]
    K1 = K[1:2]
    #K2 = K[2:3]
    #K3 = K[3:4]
    #K4 = K[4:5]
    #K5 = K[5:6]

    L, R = X[0:20], X[20:40]
    R, L = RF(L, R, K0)
    R, L = RF(L, R, K1)
    #R, L = RF(L, R, K2)
    #R, L = RF(L, R, K3)
    #R, L = RF(L, R, K4)
    #L, R = RF(L, R, K5)
    
    return R 

#Brute-forces first 3 bytes of key and stores them in a dictionary

possibleDecodings = {}
for byte1 in range(256):
    print(byte1)
    for byte2 in range(256):
        for byte3 in range(256):     
            (possibleDecodings.update({DEC2(block1, (bytes([byte1, byte2, byte3]))) : [byte1, byte2, byte3]}))

#print(len(possibleDecodings))
                 

#Brute-forces K3 based on K0, K1, K3, K4, K5
def finalKey(keyArray):
    for K3 in range(256):
        keyArray[2] = K3
        if(ENC(block1plain, bytes(keyArray)) == block1):
            return keyArray
    

#Tries encoding the plaintext with K0, K1 until a match is found with the possible decodings, then calculates the final key and decrypts the second block.
curencode = bytes(0)
for byte1 in range(256):
    print(byte1)
    for byte2 in range(256):
        curencode = ENC2(block1plain, (bytes([byte1, byte2])))
        #print(bytes_to_bits(curencode))
        if(curencode in possibleDecodings):
            print('Found a match! \nKey (without K2):')
            print([byte1, byte2] + possibleDecodings.get(curencode), '\nFull key:')
            key = finalKey([byte1, byte2, 0] + possibleDecodings.get(curencode))
            print(key)
            print(DEC(block2, bytes(key)))
            exit()

            
            
            
                
                    
                

            
            
