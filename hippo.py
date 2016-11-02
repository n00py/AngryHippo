from Crypto.Cipher import DES
import struct
import binascii
#Define params
key = ""
chall = ""
#Truncate to 8 chars
key = key[:8]
# Convert to binary
binary = (' '.join(format(ord(x), 'b') for x in key))
binaryList = binary.split()
print binaryList
count=0
#Add leading zeros
for x in binaryList:
    binaryList[count] = ("0" * (8 - len(binaryList[count]))) + binaryList[count]
    count+=1
# Function mirror the byte
def bitMirror(byte):
    return byte[::-1]
flipkey=""
# turn back into binary
print binaryList
for x in binaryList:
    print bitMirror(x)
for x in binaryList:
    flipkey += struct.pack('B', int(bitMirror(x), 2))
#Pad with NULL bytes
flipkey += "\x00" * (8 - len(flipkey))
#Crypto Stuff
des = DES.new(flipkey, DES.MODE_ECB)
#Challange from server
challenge= chall.decode("hex")

print ' '.join(x.encode('hex') for x in challenge)
response = des.encrypt(challenge)
print ' '.join(x.encode('hex') for x in response)
