#Based on Natasha.py which was given in the assignment

import numpy as np
from Crypto.Hash import SHA
from Crypto.Util.strxor import strxor 

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

def DEC(Y, K):

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
    L, R = RF(L, R, K0)
    #print(type(R), type(L))
    #X = bytes(0)
    X = strxor(L, R)
    return X

numpyArr = np.array([bytes([i,j,k]) for i in range(256) for j in range(256) for k in range(256)])

f = lambda x: DEC(block1, x)

possibleDecodings = f(numpyArr)


with open("firsthalf.bin", "wb") as binary_file:
    binary_file.write(possibleDecodings, separator = ",")
            
