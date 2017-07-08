# pdispatch
## A simple SSH client/server for remote command execution
Requires Python 3 / paramiko

## Usage:
```
usage: pokeydispatch.py [-h] [--ip [IP [IP ...]]] [--port PORT] [--user USER]
                        [--passwd PASSWD] [--host-key-file HOST_KEY_FILE]
                        [--rsa RSA] [--cmd CMD] [--timeout TIMEOUT] [-C] [-r]
                        [-v] [-i]

    This simple SSH client can be used as a remote SSH server if
    required (e.g. on Windows servers).

    Currently accepts password or public-key authentication
    methods (RSA only).  DSA and other methods to be supported
    soon.

    Usage Examples:
        ## Basic connectivity test
        $ ./sshcmd.py --rsa=/path/to/id_rsa.pub --user=<username> --ip <destination IP> --cmd "uname -a"

        ## Passwords may be passed, though keys are recommended
        $ ./sshcmd.py --user=<username> --password=<password> --ip <destination IP> --cmd "ls"

        ## Multiple destination IPs are possible
        $ ./sshcmd.py --user=<username> --rsa=<rsa_pub> --ip 12.34.56.78:122 192.168.1.12:9998

        ## If they all share a common port, use --port
        $ ./sshcmd.py --user=<username> --rsa=<rsa_pub> --port=<common port> --ip 12.34.56.78 192.168.1.12
    

optional arguments:
  -h, --help            show this help message and exit
  --ip [IP [IP ...]]    Destination host ip(s)
  --port PORT           Destination host SSH port
  --user USER           SSH Username
  --passwd PASSWD       SSH password
  --host-key-file HOST_KEY_FILE
                        Path to known_hosts
  --rsa RSA             Path to id_rsa or other key file
  --cmd CMD             Quoted command to be executed remotely
  --timeout TIMEOUT     SSH connection/command timeout
  -C, --nocolor         Disable colors in output
  -r, --remote          Execute commands sent by remote
  -v, --verbose         Enable verbose output
  -i, --interactive     Start an interactive session
```
