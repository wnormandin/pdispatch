#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# * * * * * * * * * * * * * * * * * * * *
#   pokeydispatch.py : a simple ssh client/server
#   Requires python3 & paramiko
# * * * * * * * * * * * * * * * * * * * *
#
#   MIT License
#
#   Copyright (c) 2017 William Normandin
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in all
#   copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#   SOFTWARE.
#
# * * * * * * * * * * * * * * * * * * * *

import threading
import sys
import subprocess
import argparse
import textwrap as _textwrap
from socket import timeout as TOE

try:
    import paramiko
except:
    print('Missing paramiko!')
    sys.exit(1)

USAGE= '''
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
    '''

def cli():
    parser = argparse.ArgumentParser(formatter_class=Formatter, description=USAGE)
    parser.add_argument('--ip', type=str, nargs='*', help='Destination host ip(s)', required=True)
    parser.add_argument('--port', type=int, help='Destination host SSH port (default=22)')
    parser.add_argument('--user', type=str, help='SSH Username (default=root)', default='root')
    parser.add_argument('--passwd', type=str, help='SSH password')
    parser.add_argument('--host-key-file', type=str, help='Path to known_hosts')
    parser.add_argument('--rsa', type=str, help='Path to id_rsa or other key file')
    parser.add_argument('--cmd', type=str, help='Quoted command to be executed remotely')
    parser.add_argument('--timeout', type=int, help='SSH connection/command timeout (default=5s)', default=5)
    parser.add_argument('-C', '--nocolor', action='store_true', help='Disable colors in output')
    parser.add_argument('-r', '--remote', action='store_true', help='Execute commands sent by remote')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-i','--interactive', action='store_true', help='Start an interactive session')
    return parser.parse_args()


class Formatter(argparse.RawDescriptionHelpFormatter):
    def _split_lines(self, text, width):
        text = self._whitespace_matcher.sub(' ', text).strip()
        return _textwrap.wrap(text, width)

def cprint(val, col=None, verbose=False):
    if not args.verbose and verbose:
        return
    if col==None:
        msg = val
    else:
        msg = color_wrap(val, col)
    print(msg)

def color_wrap(val, col):
    if args.nocolor:
        return str(val)
    return ''.join([col, str(val), Color.END])


class Color:
    BLACK_ON_GREEN = '\x1b[1;30;42m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    MSG = '\x1b[1;32;44m'
    ERR = '\x1b[1;31;44m'
    TST = '\x1b[7;34;46m'

def ssh_command(args):
    # Use remote=True to run as SSH server on windows
    client = paramiko.SSHClient()
    if args.host_key_file is not None:
        client.load_host_keys(filename=args.host_key_file)
    client.set_missing_host_key_policy(policy=paramiko.AutoAddPolicy())
    for ip in args.ip:
        cprint('-'*50, Color.BLUE, True)
        if '::' in ip:
            cprint('[*] IPv6 not supported: {}'.format(ip), Color.ERR)
            continue

        if ':' in ip:
            ip, port = ip.split(':')
            port = int(port)
        else:
            port = args.port

        try:
            if args.rsa is not None:
                client.connect(ip, port=port, username=args.user, key_filename=args.rsa, timeout=args.timeout)
            else:
                client.connect(ip, port=args.port, username=args.user, password=args.passwd, timeout=args.timeout)
        except (TimeoutError, TOE):
            cprint('[*] Connection to {}:{} timed out'.format(ip, port), Color.ERR)
            continue

        cprint('[*] Connected to {}:{}'.format(ip, port), Color.GREEN, True)
        ssh_session = client.get_transport().open_session()

        if ssh_session.active:
            cprint(' -  SSH session active', Color.BLUE, True)
            if args.cmd is not None:
                ssh_session.exec_command(args.cmd)
                cprint(ssh_session.recv(1024).decode())
            if args.interactive:
                pass    # Not implemented
            if args.remote:
                while True:
                    command = ssh_session.recv(1024)
                    try:
                        output = subprocess.check_output(command, shell=True)
                        ssh_session.send(output)
                    except Exception as e:
                        ssh_session.send(str(e))
            client.close()
    return

if __name__=='__main__':
    try:
        global args
        args = cli()
        ssh_command(args)
    except KeyboardInterrupt:
        ssh_command.client.close()
