#!/usr/bin/env python
''' client.py '''

import sys
import socket
import hashlib
from datetime import datetime
import binascii
import sys
import os
import argparse
import random
import string

from protocol import Protocol
from errors import BadKeyError

class Client(Protocol):
    __NONCE_LENGTH = 16

    def __init__(self, sock, secret, cipher_type):
        super(Client, self).__init__(sock, secret)
        self.cipher_type = cipher_type
        self.nonce = Client.__generate_nonce()
        super(Client, self).init_utils(cipher_type, self.nonce)

    def handshake(self):
        ''' Perform the handshake with the server '''
        # Send the cipher and nonce
        super(Client, self).send_plain_message('{0},{1}'.format(self.cipher_type, self.nonce))
        super(Client, self).rec_ack()

        # Perform authentication
        self.send_message(self.challenge())
        super(Client, self).rec_ack()

        # Handshake successful
        Protocol.log('handshake successful')
        return

    def download(self, filename):
        ''' Download file from server '''
        self.send_message('download')
        ack = self.receive_message() # needed this to run on lab computers
        self.send_message(filename)
        msg = self.receive_message()
        self.send_message('ok') # needed this to run on lab computers

    	# file found
        if not msg.startswith('Fail!'):

            data = self.receive_data()
            while data:
                sys.stdout.buffer.write(data)
                data = self.receive_data()
            print('Download complete!', file=sys.stderr)
            return

    	# if file not found
        else:
            print("File doesn't exist!", file=sys.stderr)

    def upload(self, filename):
        ''' Upload file to server '''
        self.send_message('upload')
        ack = self.receive_message() # needed this to run on lab compute
        self.send_message(filename)
        ack = self.receive_message() # needed this to run on lab compute

        bytesToSend = sys.stdin.buffer.read(BUFFER_SIZE-1)
        while bytesToSend:
            self.send_data(bytesToSend)
            bytesToSend = sys.stdin.buffer.read(BUFFER_SIZE-1)

        print('Upload complete!', file=sys.stderr)
        return

    @staticmethod
    def __generate_nonce():
        ''' Generate a random nonce to send to the server '''
        return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(Client.__NONCE_LENGTH))


def parse_args():
    '''
    Handles parsing arguments
    Reference: https://docs.python.org/3/library/argparse.h
    '''

    usage = 'python3 client.py command filename hostname:port cipher key'
    parser = argparse.ArgumentParser(usage=usage)

    # arugments to be parsed
    parser.add_argument('command', type=str, help='The command argument will \
    determine if the client will be uploading or downloading data to/from the server. \
    Valid values are write and read.')

    parser.add_argument('filename', type=str, help='The filename argument specifies \
    the name of the file to be used by the server application')

    parser.add_argument('hostname_port', type=str, help='The hostname:port argument \
    specifies the address of the server, and the port on which the server is listening. \
    The hostname can be specified as a domain name or an IPv4 address. \
    he port will be an integer in range 0-65535.')

    parser.add_argument('cipher', type=str, help='The cipher argument specifies which \
    cipher is to be used for encrypting the communication with the server. Valid values \
    are aes256, aes128 and null.')

    parser.add_argument('key', type=str, help='The key parameter specifies a secret key \
    that must match the server’s secret key. This key will be also used to derive both \
    the session keys and the initialization vectors.')

    # parse arguments
    args = parser.parse_args()

    # error checking
    if args.command not in ('read', 'write'):
        print("Error, client only supports 'read' or 'write'")
        parser.exit('Usage: ' + usage)

    if ':' not in args.hostname_port:
        print('Error, format --> hostname:port')
        parser.exit('Usage: ' + usage)

    _, port = args.hostname_port.split(':')
    if int(port) not in range(0, 65536):
        print('Error, port must be 0-65535')
        parser.exit('Usage: ' + usage)

    if args.cipher not in Protocol.CIPHERS:
        print('Error, cipher must be: aes128, aes256, or null')
        parser.exit('Usage: {}'.format(usage))

    # return arguments to main
    return args


def main():
    ''' Main '''
    args = parse_args()

    host, port = args.hostname_port.split(':')

    # connect to server
    conn = socket.socket()
    conn.connect((host, int(port)))

    # start client program
    client = Client(conn, args.key, args.cipher)
    try:
        client.handshake()
    except BadKeyError:
        Protocol.log('invalid key used')

    # handle command
    command = args.command
    if command == 'read':
        client.download(args.filename)
    elif command == 'write':
        client.upload(args.filename)
    else:
        print('Unsupported command', file=sys.stderr)

    # close socket
    Protocol.log('Disconnecting from server')
    conn.close()


if __name__ == '__main__':
    main()
