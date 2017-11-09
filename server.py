#!/usr/bin/env python
#server.py

import string
import socket
import hashlib
from datetime import datetime
import binascii
import sys
import os
import argparse
from Crypto.Cipher import AES

# globals
BUFFER_SIZE = 16
CIPHERS = [
	'null',
	'aes128',
	'aes256'
]
HOST = '127.0.0.1'
PORT = 8000
DEBUG = True

SECRET_KEY = "blabjfkdsl"
SESSION_KEY = '0000000000000000'
iv = '0000000000000000'

'''
Handles encrypting data
'''
def encrypt(data):
	encryptor = AES.new(SESSION_KEY, AES.MODE_CBC, IV=iv)

	# pad
	length = 16 - (len(data) % 16)
	data += bytes([length])*length

	return encryptor.encrypt(data)

'''
Handles decrypting data
'''
def decrypt(data):
	encryptor = AES.new(SESSION_KEY, AES.MODE_CBC, IV=iv)
	# remove padding
	data = encryptor.decrypt(data)
	data = data[:-data[-1]]
	return data

'''
Handles sending messages to client
'''
def sendMsg(sock, str):
	if DEBUG:
		print('Sent: ' + str)
	sock.send(encrypt(str.encode('utf-8')))

'''
Handles sending data to client
'''
def sendData(sock, data):
	sock.send(encrypt(data))

'''
Handles receiving messages from client
'''
def recvMsg(sock):
	msg = sock.recv(BUFFER_SIZE)
	msg = decrypt(msg).decode('utf-8')
	if DEBUG:
		print('Recvd: ' + msg)
	return msg

'''
Handles receiving data from client
'''
def recvData(sock):
	data = sock.recv(BUFFER_SIZE)
	data = decrypt(data)
	return data

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
