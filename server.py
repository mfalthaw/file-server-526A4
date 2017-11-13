#!/usr/bin/env python
''' server.py '''

import socket
from datetime import datetime
import binascii
import sys
import os
import argparse
import uuid

from protocol import Protocol
from errors import BadKeyError

# Constants
HOST = '127.0.0.1'


class ClientHandler(Protocol):
    ''' Handler for clients '''

    def handshake(self):
        ''' Perform handshake with client '''
        # Receive the cipher and nonce
        msg = super(ClientHandler, self).get_plain_message()
        cipher_type, nonce = msg.split(',')
        super(ClientHandler, self).init_utils(cipher_type, nonce)
        challenge = self.build_challenge()
        self.send_message(challenge)

        # Perform authentication, receive challenge
        expected_hash = super(ClientHandler, self).hash_challenge(challenge)
        actual_hash = self.receive_message()
        if expected_hash != actual_hash:
            # Failed, the keys do not match
            super(ClientHandler, self).send_ack(Protocol.BAD_KEY_ACK)
            return False

        # Successful challenge
        super(ClientHandler, self).send_ack(Protocol.OK_ACK)

        # Server has authenticated client
        Protocol.log('handshake successful')
        return True

    def handleTask(self):
        ''' Handle client task '''
        task = self.receive_message()
        self.send_ack(Protocol.OK_ACK)
        if task.lower() == 'upload':
        	self.receiveFile()
        elif task.lower() == 'download':
        	self.sendFile()
        else:
        	self.send_message("Supported tasks: upload or download")

    def sendFile(self):
        ''' Send a file to client '''
        fileName = self.receive_message()
        Protocol.log('File Name received: {}'.format(fileName))
        if os.path.isfile(fileName):
            self.send_message('File Found!')
            self.rec_ack()

    		# start sending file
            with open(fileName, 'rb') as file:
                bytesToSend = file.read(Protocol.BUFFER_SIZE-1)
                while bytesToSend:
                    self.send_data(bytesToSend)
                    bytesToSend = file.read(Protocol.BUFFER_SIZE-1)

                Protocol.log('File transfer completed!')
                file.close()

    	# file not found
        else:
            Protocol.log('Error: file could not be read by the server.\n\t\tCan\'t find: {}'.format(fileName))
            self.send_message("Fail! Can't find: {}".format(fileName))
            self.rec_ack()
        return

    def receiveFile(self):
        ''' Receive a file from client '''
        fileName = self.receive_message()
        self.send_ack(Protocol.OK_ACK)
        Protocol.log('File Name received: {}'.format(fileName))

        # create a file
        file = open(fileName, 'wb')
        data = self.receive_data()
        while data:
            file.write(data)
            data = self.receive_data()

        Protocol.log('Upload complete!')
        file.close()
        return

    def build_challenge(self):
        ''' Create a random string for challenge '''
        return str(uuid.uuid4())


def parse_args():
    '''
    Handles parsing arguments
    Reference: https://docs.python.org/3/library/argparse.h
    '''

    usage = 'python3 server.py port key'
    parser = argparse.ArgumentParser(usage=usage)
    # arugments to be parsed
    parser.add_argument('port', type=int, help='port to listen on')
    parser.add_argument('key', type=str, help='The key parameter specifies a secret key \
    that must match the server’s secret key. This key will be also used to derive both \
    the session keys and the initialization vectors.')

    # parse arguments
    args = parser.parse_args()
    
    # error checking
    if int(args.port) not in range(0, 65536):
        Protocol.log('Error: wrong command line arguments.\n\t\tport must be 0-65535')
        parser.exit('Usage: ' + usage)

    # return arguments to main
    return args


def handle_client(sock, secret):
    ''' Handle new client '''
    client_handler = ClientHandler(sock, secret)
    if not client_handler.handshake():
        return 'Failed handshake'
    Protocol.log('Passed handshake')

    # hanle client task
    client_handler.handleTask()
    return

def main():
    ''' Main function '''

    # parse args
    args = parse_args()

    # initilize socket & listen for connections
    s = socket.socket()

    # handles 'port in use'
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, args.port))
    s.listen(5)


    Protocol.log('Listening on {}:{}'.format(str(HOST), str(args.port)))
    Protocol.log('Using secret key: {}'.format(args.key))
    # while True:
    conn, addr = s.accept()
    addr = str(addr)
    Protocol.log('{}: New connection from: {}'.format(datetime.now().strftime('%H:%M:%S'), addr))
    try:
        handle_client(conn, args.key)
    except BadKeyError:
        Protocol.log('Error: wrong key.\n\t\tInvalid encryption key used, closing connection')

    # close connection
    Protocol.log('closed connection!')
    conn.close()


if __name__ == '__main__':
    main()
