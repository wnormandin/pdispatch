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

    Execute commands via ssh

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
    parser.add_argument('--rsa', type=str, help='Path to rsa key file')
    parser.add_argument('--cmd', type=str, help='Quoted command to be executed remotely')
    parser.add_argument('--timeout', type=int, help='SSH connection/command timeout (default=5s)', default=5)
    parser.add_argument('-s', '--server', action='store_true', help='Run in SSH server mode')
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

class Server:

    def __init__(self, args):
        self.args = args

class Client:

    def __init__(self, args):
        self.args = args
        self.client = paramiko.SSHClient()
        if self.args.host_key_file is not None:
            self.client.load_host_keys(filename=self.args.host_key_file)
        self.client.set_missing_host_key_policy(policy=paramiko.AutoAddPolicy())

    def cxn_params(self, ip):
        if '::' in ip:
            cprint('[*] IPv6 not supported: {}'.format(ip), Color.ERR)
            return False
        if ':' in ip:
            ip, port = ip.split(':')
            return ip, int(port)
        return ip, self.args.port

    def execute(self):
        for item in args.ip:
            cprint('-'*50, Color.BLUE, True)
            params = self.cxn_params(item)
            if params:
                ip, port = params
                try:
                    self.connect(ip, port)
                except (TimeoutError, TOE):
                    cprint('[!] Connection to {}:{} timed out'.format(
                                                    ip, port), Color.ERR)
                    continue
                cprint('[*] Connected to {}:{}'.format(ip, port), Color.GREEN, True)
                self.ssh_session = self.client.get_transport().open_session()
                self.session_run()
                self.disconnect()

    def connect(self, ip, port):
        if self.args.rsa is not None:
            self.client.connect(ip, port=port, username=self.args.user,
                    key_filename=self.args.rsa, timeout=self.args.timeout)
        else:
            self.client.connect(ip, port=port, username=self.args.user,
                    password=self.args.passwd, timeout=self.args.timeout)

    def disconnect(self):
        self.client.close()

    def session_run(self):
        if self.ssh_session.active:
            cprint(' - SSH session active', Color.BLUE, True)
            if self.args.cmd is not None:
                self.ssh_session.exec_command(args.cmd)
                cprint(self.ssh_session.recv(1024).decode().rstrip())
            if self.args.interactive:
                pass
            if self.args.remote:
                while True:
                    command = self.ssh_session.recv(1024)
                    if command == "DISCONNECT":
                        return
                    try:
                        output = subprocess.check_output(command, shell=True)
                        self.ssh_session.send(output)
                    except Exception as e:
                        self.ssh_session.send(str(e))
                self.client.close()

if __name__=='__main__':
    try:
        args = cli()
        if args.server:
            app = Server(args)
        else:
            app = Client(args)
        app.execute()
    except KeyboardInterrupt:
        cprint('[*] Keyboard interrupt detected, aborting', Color.ERR)
        if not args.server:
            app.client.close()
        sys.exit(1)
