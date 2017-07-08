# pokeydispatch
## A simple SSH client/server for remote command execution and reverse SSH shell
Requires Python 3 / paramiko

## Usage:
```
usage: pokeydispatch.py [-h] --ip [IP [IP ...]] [--port PORT] [--user USER]
                        [--passwd PASSWD] [--host-key-file HOST_KEY_FILE]
                        [--rsa RSA] [--cmd CMD] [--timeout TIMEOUT] [-s] [-C]
                        [-r] [-v] [-i] [-d]

    Execute commands via ssh

    Currently accepts password or public-key authentication
    methods (RSA only).  DSA and other methods to be supported
    soon.

    Usage Examples:
        * Basic connectivity test
        $ ./pokeydispatch.py --rsa=/path/to/id_rsa.pub --user=<username> --ip <destination IP> --cmd "uname -a"

        * Passwords may be passed, though keys are recommended
        $ ./pokeydispatch.py --user=<username> --password=<password> --ip <destination IP> --cmd "ls"

        * Multiple destination IPs are possible
        $ ./pokeydispatch.py --user=<username> --rsa=<rsa_pub> --ip 12.34.56.78:122 192.168.1.12:9998

        * If they all share a common port, use --port
        $ ./pokeydispatch.py --user=<username> --rsa=<rsa_pub> --port=<common port> --ip 12.34.56.78 192.168.1.12

        * To run as a server, pass --server.  Various arguments are handled differently:
            --ip:       bind IP address
            --port:     bind port
            --rsa:      the host rsa key
            --user:     client username
            --passwd:   client password

        * In server mode, the following arguments are ignored:
            --cmd
            --host-key-file
            -i | --interactive
            -r | --remote

    Server Example:
        * This example demonstrates basic server usage, listening @ 127.0.0.1:9998 for the user <username> with password <password>
        $ ./pokeydispatch.py --rsa=/path/to/host_key --user=<username> --passwd=<password> --ip=127.0.0.1 --port=9998 --server -v

    

optional arguments:
  -h, --help            show this help message and exit
  --ip [IP [IP ...]]    Destination host ip(s)
  --port PORT           Destination host SSH port (default=22)
  --user USER           SSH Username (default=root)
  --passwd PASSWD       SSH password
  --host-key-file HOST_KEY_FILE
                        Path to known_hosts
  --rsa RSA             Path to rsa key file
  --cmd CMD             Quoted command to be executed remotely
  --timeout TIMEOUT     SSH connection/command timeout (default=5s)
  -s, --server          Run in SSH server mode
  -C, --nocolor         Disable colors in output
  -r, --remote          Execute commands sent by remote
  -v, --verbose         Enable verbose output
  -i, --interactive     Start an interactive session
  -d, --debug           Raise exceptions
```
# Reverse SSH Server

By using the --server mode, an SSH server can be set up which awaits connections
from a remote client.  This allows remote execution (Server -> Client) in cases
when the client might not have an SSH server (e.g most windows boxes).

## Server Side
```
# python pokeydispatch.py --rsa=id_rsa --user=bill --passwd=tst --ip 127.0.0.1 --port=9998 --server -v
[*] Starting ssh server
 -  Binding to host 127.0.0.1:9998
 -  Listening for connections
[*] Session initiated from ('127.0.0.1', 36225)
 -  Server keys added
 -  Server started
[*] Authenticated
ClientConnected
 -  Getting command
Command: ls
cgi-bin
end_times
favicon.ico
mailprobs.sh
pokeydispatch.py
pokeyproxy.py
pokeyscan.py
pokeysniff.py
project_euler.py
README.pyx
smtp_mailer.py
tcp_client.py
tcp_server.py


 -  Getting command
Command: uname -a
Linux server.test.us 2.6.32-696.3.1.el6.x86_64 #1 SMP Tue May 30 19:52:55 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux


 -  Getting command
Command: quit
[*] Exiting
```

## Client Side
```
# python pokeydispatch.py --ip 127.0.0.1 --port 9998 --user bill --passwd tst --cmd 'ClientConnected' -v --remote
--------------------------------------------------
[*] Connected to 127.0.0.1:9998
 - SSH session active
Welcome to pokey_ssh
[*] Command received: ls
 -  Sending 14 lines
[*] Command received: uname -a
 -  Sending 2 lines
[*] Exit signal received
```
