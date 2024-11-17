from Crypto.Util.strxor import strxor 
from Crypto.Hash import MD5
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES
import sys

#defs
startstate = bytes.fromhex('b5562ff25e66e602eae4dbd61b2d5e8b')
inputfile = "challenges/02_Iterative_guessing/message.bin"
outputfile = "challenges/02_Iterative_guessing/plainmessage.txt"

postimestamps = []
mil = 0
sec = 0
#Brute force seconds
knownstr = '202203191209'
for i in range(6000):
    postimestamps.append(knownstr + f"{sec:02d}" + f"{mil:02d}")
    if i % 100 == 0 :
        sec += 1
        mil = 0
    else:
        mil += 1


poskeys = []
for timestamp in postimestamps:
    hasher = MD5.new()
    prehash = strxor(startstate, timestamp.encode('ascii'))
    hasher.update(prehash)
    poskeys.append(hasher.digest())


ifile = open(inputfile, 'rb')
msg = ifile.read()
ifile.close()

# parse the message
header_length = 9                                          # header is 9 bytes long
header = msg[0:header_length]
iv = msg[header_length:header_length+AES.block_size]       # iv is AES.block_size bytes long
mac_length = 32                                            # SHA256 hash is 32 bytes long
encrypted = msg[header_length+AES.block_size:-mac_length]  # encrypted part is between iv and mac
mac = msg[-mac_length:]                                    # last mac_length bytes form the mac
header_version = header[0:2]        # version is encoded on 2 bytes 
header_type = header[2:3]           # type is encoded on 1 byte 
header_length = header[3:5]         # msg length is encoded on 2 bytes 
header_sqn = header[5:9]            # msg sqn is encoded on 4 bytes 

print("Message header:")
print("   - protocol version: " + header_version.hex() + " (" + str(header_version[0]) + "." + str(header_version[1]) + ")")
print("   - message type: " + header_type.hex() + " (" + str(int.from_bytes(header_type, byteorder='big')) + ")")
print("   - message length: " + header_length.hex() + " (" + str(int.from_bytes(header_length, byteorder='big')) + ")")
print("   - message sequence number: " + header_sqn.hex() + " (" + str(int.from_bytes(header_sqn, byteorder='big')) + ")")



for key in poskeys:
    # verify the mac
    #print("MAC verification is being performed...")
    MAC = HMAC.new(key, digestmod=SHA256)
    MAC.update(header)
    MAC.update(iv)
    MAC.update(encrypted)
    comp_mac = MAC.digest()
    #print(comp_mac.hex())

    if comp_mac == mac:
        print('Mac key: ', key)
        mackey = key
    

newstate = strxor(mackey, startstate)



for timestamp in postimestamps:
    curkey = strxor(newstate, timestamp.encode('ascii'))
    hasher = MD5.new()
    hasher.update(curkey)
    curkey = hasher.digest()
    #print("Testing timestamp:", timestamp)
    #print("Derived curkey:", curkey.hex())
    # decrypt the encrypted part
    #print("Decryption is attempted...")
    ENC = AES.new(curkey, AES.MODE_CBC, iv)
    decrypted = ENC.decrypt(encrypted)

    # remove and check padding
    i = -1
    while (decrypted[i] == 0): i -= 1
    padding = decrypted[i:]
    decrypted = decrypted[:i]
    if (padding[0] == 0x80 and b'FLAG' in decrypted):
        output = open(outputfile, 'wb')
        print("Padding is successfully removed.")               
        output.write(decrypted)
        print("Payload is saved to " + outputfile)
        print('enc key: ', curkey)
        output.close()
        quit()
              


    