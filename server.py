#!/usr/bin/env python
#server.py

import string
import socket
import threading
from datetime import datetime
import os
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

# Constants
BUFFER_SIZE = 1024
HOST = '127.0.0.1'
PORT = 8000
DEBUG = True

# Ciphers
AES128 = 'aes128'
AES256 = 'aes256'
NULL = 'null'

'''
Handles sending messages to client
'''
def sendMsg(sock, msg, protocol):
	if DEBUG:
		print('protocol: {}'.format(protocol))
		print('message: {}'.format(msg))

	if not protocol:
		raise ValueError('should have specified a protocol')

	# sock.send(msg.encode('utf-8')) TODO: Replace
	raise NotImplementedError()

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
	sendMsg(sock, 'ok') # needed this to run on lab computers
	print('File Name received: {}'.format(fileName))

	# create a file
	file = open('UPLOADED_' + fileName, 'wb')
	data = recvData(sock)
	sendMsg(sock, 'ok') # needed this to run on lab computers
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
		ack = recvMsg(sock) # needed this to run on lab computers
		fileSize = os.path.getsize(fileName)

		# start sending file
		with open(fileName, 'rb') as file:
			bytesToSend = file.read(BUFFER_SIZE)
			sendData(sock, bytesToSend)
			ack = recvMsg(sock) # needed this to run on lab computers

			while bytesToSend:
				bytesToSend = file.read(BUFFER_SIZE)
				sendData(sock, bytesToSend)

			print('File transfer completed!')
			file.close()
			return

	# file not found
	else:
		sendMsg(sock, "Fail! Can't find: {}".format(fileName))
		ack = recvMsg(sock) # needed this to run on lab computers
		return

'''
Perform the handshake with the client
'''
def serverHandshake():
	# Receive the cipher and noonce


	# Perform authentication


	# Server has authenticated client
	raise NotImplementedError()

'''
Handle new client
'''
def handleClient(name, sock):
	task = recvMsg(sock)
	sendMsg(sock, 'ok') # needed this to run on lab computers
	if task.lower() == 'upload':
		receiveFile(sock)
	elif task.lower() == 'download':
		sendFile(sock)
	else:
		sendMsg(sock, "Supported tasks: upload or download")

def Main():
	# initilize socket & listen for connections
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # handles 'port in use'
	s.bind((HOST, PORT))
	s.listen(5)
	print('Server started! Listening on {}:{}...'.format(str(HOST), str(PORT)))

	conn, addr = s.accept()
	print('{}: New connection from: {}'.format(datetime.now().strftime('%H:%M:%S'), str(addr)))
	handleClient('name', conn)

	# close connection
	s.close()

if __name__ == '__main__':
	Main()
