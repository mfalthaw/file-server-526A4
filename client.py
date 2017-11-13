#!/usr/bin/env python
''' client.py '''

import socket
from datetime import datetime
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
        challenge = self.receive_message()

        # Perform authentication
        hash_challenge = super(Client, self).hash_challenge(challenge)
        self.send_message(hash_challenge)
        super(Client, self).rec_ack()

        # Handshake successful
        Protocol.log('handshake successful')
        return

    def download(self, filename):
        ''' Download file from server '''
        self.send_message('download')
        self.rec_ack()
        self.send_message(filename)
        msg = self.receive_message()
        self.send_ack(Protocol.OK_ACK)

    	# file found
        if not msg.startswith('Fail!'):

            data = self.receive_data()
            while data:
                sys.stdout.buffer.write(data)
                data = self.receive_data()
            Protocol.log('Download complete!')
            return

    	# if file not found
        else:
            Protocol.log("File doesn't exist!")

    def upload(self, filename):
        ''' Upload file to server '''
        self.send_message('upload')
        self.rec_ack()
        self.send_message(filename)
        self.rec_ack()

        bytesToSend = sys.stdin.buffer.read(Protocol.BUFFER_SIZE-1)
        while bytesToSend:
            self.send_data(bytesToSend)
            bytesToSend = sys.stdin.buffer.read(Protocol.BUFFER_SIZE-1)

        Protocol.log('Upload complete!')
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
        Protocol.log("Error, client only supports 'read' or 'write'")
        parser.exit('Usage: ' + usage)

    if ':' not in args.hostname_port:
        Protocol.log('Error, format --> hostname:port')
        parser.exit('Usage: ' + usage)

    _, port = args.hostname_port.split(':')
    if int(port) not in range(0, 65536):
        Protocol.log('Error, port must be 0-65535')
        parser.exit('Usage: ' + usage)

    if args.cipher not in Protocol.CIPHERS:
        Protocol.log('Error, cipher must be: aes128, aes256, or null')
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

        # handle command
        command = args.command
        if command == 'read':
            client.download(args.filename)
        elif command == 'write':
            client.upload(args.filename)
        else:
            Protocol.log('Unsupported command')

    except BadKeyError:
        Protocol.log('invalid key used')

    # close socket
    Protocol.log('Disconnecting from server')
    conn.close()


if __name__ == '__main__':
    main()
