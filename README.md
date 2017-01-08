# AngryHippo - Exploitation Toolset for HippoConnect Protocol
```
                   /\____/\            _
                  /   ..   \          /_\  _ __   __ _ _ __ _   _
                 /  \    /  \        //_\\| '_ \ / _` | '__| | | |
                | 'X'    'X' |      /  _  \ | | | (_| | |  | |_| |
               / ____________ \     \_/ \_/_| |_|\__, |_|   \__, |
             , ,'    `--'    '. .              _  |___/      |___/
            _| |              | |_       /\  /(_)_ __  _ __   ___
          /  ' '              ' '  \    / /_/ / | '_ \| '_ \ / _ \
         (    `,',__________.','    )  / __  /| | |_) | |_) | (_) |
          \_    ` .V______V, '    _/   \/ /_/ |_| .__/| .__/ \___/
             |                  |               |_|   |_|
             |    ,-.    ,-.    |
              \      ).,(      /       HippoRemote Hacking Toolset
                \___/    \___/                  ~n00py~

```
## ABOUT:
This script was designed to attack the HippoConnect protocol which is used with the HippoRemote iPhone app and the HippoConnect listener.

## INSTALL:

All dependancies are met on a default installation of OS X.  

## USAGE:

### Sniffing with Angry Hippo
```
python hippo.py --sniff
```
### Cracking with Angry Hippo
```
python hippo.py --crack --wordlist [PATH TO WORDLIST] --challenge [CHALLENGE] --response [RESPONSE]
```
### Keystroke injection with Angry Hippo
```
python hippo.py --inject --target [VICTIM] --port [LISTENER_PORT] --key [PASSWORD] --address [LISTENER_IP] --timing [SECONDS]

```

For more information view the blog post located here: https://www.n00py.io/2017/01/control-your-mac-with-an-iphone-app-an-analysis-of-hipporemote/

###Future Ideas:
- Add multi-processing to the cracking module
- TCP hijacking w/ raw sockets if MITM to inject keystrokes without knowing the password
