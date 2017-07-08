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
import socket
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
        * Basic connectivity test
        $ ./sshcmd.py --rsa=/path/to/id_rsa.pub --user=<username> --ip <destination IP> --cmd "uname -a"

        * Passwords may be passed, though keys are recommended
        $ ./sshcmd.py --user=<username> --password=<password> --ip <destination IP> --cmd "ls"

        * Multiple destination IPs are possible
        $ ./sshcmd.py --user=<username> --rsa=<rsa_pub> --ip 12.34.56.78:122 192.168.1.12:9998

        * If they all share a common port, use --port
        $ ./sshcmd.py --user=<username> --rsa=<rsa_pub> --port=<common port> --ip 12.34.56.78 192.168.1.12

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
    parser.add_argument('-d', '--debug', action='store_true', help='Raise exceptions')
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

class Server(paramiko.ServerInterface):

    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, channel_id):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username == args.user and password == args.passwd:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def listen(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            cprint(' -  Binding to host {}:{}'.format(args.ip, args.port), Color.BLUE, True)
            self.sock.bind((args.ip, args.port))
            self.sock.listen(100)
            cprint(' -  Listening for connections', Color.BLUE, True)
            client, c_addr = self.sock.accept()
        except Exception as e:
            if args.debug:
                raise
            cprint('[!] Listen failed: {}'.format(e), Color.ERR)
            sys.exit(1)
        else:
            cprint('[*] Session initiated from {}'.format(c_addr), Color.MSG, True)
            return client, c_addr

class Client:

    def __init__(self):
        self.client = paramiko.SSHClient()
        if args.host_key_file is not None:
            self.client.load_host_keys(filename=args.host_key_file)
        self.client.set_missing_host_key_policy(policy=paramiko.AutoAddPolicy())

    def cxn_params(self, ip):
        if '::' in ip:
            cprint('[*] IPv6 not supported: {}'.format(ip), Color.ERR)
            return False
        if ':' in ip:
            ip, port = ip.split(':')
            return ip, int(port)
        return ip, args.port

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
                self.session_run()
                self.disconnect()

    def connect(self, ip, port):
        if args.rsa is not None:
            self.client.connect(ip, port=port, username=args.user,
                    key_filename=args.rsa, timeout=args.timeout)
        else:
            self.client.connect(ip, port=port, username=args.user,
                    password=args.passwd, timeout=args.timeout)

    def disconnect(self):
        self.client.close()

    def session_run(self):
        self.ssh_session = self.client.get_transport().open_session()
        if self.ssh_session.active:
            cprint(' - SSH session active', Color.BLUE, True)
            if args.cmd is not None:
                if args.remote:
                    self.ssh_session.send(args.cmd)
                    cprint(self.ssh_session.recv(1024).decode().rstrip())
                else:
                    self.ssh_session.exec_command(args.cmd)
            if args.interactive:
                pass
            if args.remote:
                while True:
                    if not self.ssh_session.active:
                        self.ssh_session = self.client.get_transport().open_session()
                    command = self.ssh_session.recv(1024)
                    if command == "DISCONNECT":
                        return
                    try:
                        output = subprocess.check_output(command, shell=True)
                        self.ssh_session.send(output)
                    except Exception as e:
                        self.ssh_session.send(str(e))
                self.client.close()

def run_server():
    cprint('[*] Starting ssh server', Color.MSG)
    assert len(args.ip) == 1, 'A single bind IP must be specified in server mode'
    args.ip = args.ip[0]
    app = Server()
    client, c_addr = app.listen()
    global sess
    sess = paramiko.Transport(client)
    sess.add_server_key(paramiko.RSAKey(filename=args.rsa))
    cprint(' -  Server keys added', Color.BLUE, True)
    try:
        sess.start_server(server=app)
        cprint(' -  Server started', Color.BLUE, True)
    except paramiko.SSHException as e:
        if args.debug:
            raise
        cprint('[!] SSH Negotiation failed', Color.ERR)
    chan = sess.accept(20)
    if chan is None:
        raise AssertionError('Channel is None')
    cprint('[*] Authenticated', Color.MSG)
    cprint(chan.recv(1024).decode())
    chan.send('Welcome to pokey_ssh')
    while True:
        try:
            cprint(' -  Getting command', Color.BLUE, True)
            cmd = input('Command: ').rstrip()
            if cmd.lower() != 'exit' and cmd.lower() != 'quit':
                chan.send(cmd)
                cprint(chan.recv(1024).decode() + '\n')
            else:
                chan.send('exit')
                cprint('[*] Exiting', Color.MSG)
                sess.close()
                raise Exception('exit')
        except KeyboardInterrupt:
            sess.close()


if __name__=='__main__':
    try:
        global args
        args = cli()
        if args.server:
            run_server()
        else:
            app = Client()
            app.execute()
    except KeyboardInterrupt:
        cprint('[*] Keyboard interrupt detected, aborting', Color.ERR)
        if not args.server:
            app.client.close()
        sys.exit(1)
    except Exception as e:
        cprint('[!] Unhandled exception: {}'.format(e), Color.ERR)
        try:
            sess.close()
        except:
            pass
        if args.debug:
            raise
