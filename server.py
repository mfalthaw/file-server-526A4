#!/usr/bin/env python
# server.py

import socket
from datetime import datetime
import os
import argparse

from protocol import Protocol

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
        super(ClientHandler, self).send_ack(Protocol.OK_ACK)

        # Perform authentication, receive challenge
        expected_hash = super(ClientHandler, self).challenge()
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


def sendMsg(sock, msg, protocol):
    ''' Handles sending messages to client '''
    if DEBUG:
        print('protocol: {}'.format(protocol))
        print('message: {}'.format(msg))

    if not protocol:
        raise ValueError('should have specified a protocol')

    sock.send(msg.encode('utf-8'))


'''
Handles sending data to client
'''


def sendData(sock, data):
    sock.send(data)


'''
Handles receiving messages from client
'''


def recvMsg(sock):
    msg = sock.recv(BUFFER_SIZE).decode('utf-8')
    if DEBUG:
        print('Recvd: ' + msg)
    return msg


'''
Handles receiving data from client
'''


def recvData(sock):
    return sock.recv(BUFFER_SIZE)


'''
Handles receiving files from client
'''


def receiveFile(sock):
    fileName = recvMsg(sock)
    sendMsg(sock, 'ok')  # needed this to run on lab computers
    print('File Name received: {}'.format(fileName))

    # create a file
    file = open('UPLOADED_' + fileName, 'wb')
    data = recvData(sock)
    sendMsg(sock, 'ok')  # needed this to run on lab computers
    file.write(data)
    while data:
        data = recvData(sock)
        file.write(data)

    print('Upload complete!')
    file.close()
    return


'''
Handles sending files to client
'''


def sendFile(sock):
    fileName = recvMsg(sock)

    print('File Name received: {}'.format(fileName))
    if os.path.isfile(fileName):
        sendMsg(sock, 'File Found!')
        ack = recvMsg(sock)  # needed this to run on lab computers
        fileSize = os.path.getsize(fileName)

        # start sending file
        with open(fileName, 'rb') as file:
            bytesToSend = file.read(BUFFER_SIZE)
            sendData(sock, bytesToSend)
            ack = recvMsg(sock)  # needed this to run on lab computers

            while bytesToSend:
                bytesToSend = file.read(BUFFER_SIZE)
                sendData(sock, bytesToSend)

            print('File transfer completed!')
            file.close()
            return

    # file not found
    else:
        sendMsg(sock, "Fail! Can't find: {}".format(fileName))
        ack = recvMsg(sock)  # needed this to run on lab computers
        return

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

    # return arguments to main
    return args


def handle_client(sock, secret):
    ''' Handle new client '''
    client_handler = ClientHandler(sock, secret)
    if not client_handler.handshake():
        return 'Failed handshake'

    return 'Passed handshake'


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

    print('Server started! Listening on {}:{}...'.format(str(HOST), str(args.port)))
    while True:
        conn, addr = s.accept()
        addr = str(addr)
        print('{}: New connection from: {}'.format(datetime.now().strftime('%H:%M:%S'), addr))
        Protocol.log(handle_client(conn, args.key))

        # close connection
        Protocol.log('closed connection!')
        conn.close()


if __name__ == '__main__':
    main()
