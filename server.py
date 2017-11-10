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
BUFFER_SIZE = 32
HOST = '127.0.0.1'
DEBUG = True

SECRET_KEY = "0000000000000000"
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
		print('Sent: ' + str, file=sys.stderr)
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
		print('Recvd: ' + msg, file=sys.stderr)
	return msg

'''
Handles receiving data from client
'''
def recvData(sock):
	data = sock.recv(BUFFER_SIZE)
	return decrypt(data)

'''
Handles receiving files from client
'''
def receiveFile(sock):
	fileName = recvMsg(sock)
	sendMsg(sock, 'ok') # needed this to run on lab computers
	print('File Name received: {}'.format(fileName), file=sys.stderr)

	# create a file
	file = open(fileName, 'wb')
	data = recvData(sock)
	sendMsg(sock, 'ok') # needed this to run on lab computers
	file.write(data)
	while data:
		data = recvData(sock)
		file.write(data)

	print('Upload complete!', file=sys.stderr)
	file.close()
	return

'''
Handles sending files to client
Reads file 31 Bytes at a time; 32-1=31 so padding comes up to 32
'''
def sendFile(sock):
	fileName = recvMsg(sock)

	print('File Name received: {}'.format(fileName), file=sys.stderr)
	if os.path.isfile(fileName):
		sendMsg(sock, 'File Found!')
		ack = recvMsg(sock) # needed this to run on lab computers
		# fileSize = os.path.getsize(fileName)

		# start sending file
		with open(fileName, 'rb') as file:
			# 32-1=31 so padding comes up to 32
			bytesToSend = file.read(BUFFER_SIZE-1)
			sendData(sock, bytesToSend)
			# ack = recvMsg(sock) # needed this to run on lab computers

			while bytesToSend:
				# sendData(sock, bytesToSend)
				bytesToSend = file.read(BUFFER_SIZE-1)
				sendData(sock, bytesToSend)

			print('File transfer completed!', file=sys.stderr)
			file.close()
			return

	# file not found
	else:
		sendMsg(sock, "Fail! Can't find: {}".format(fileName))
		ack = recvMsg(sock) # needed this to run on lab computers
		return

'''
Handles parsing arguments
Reference: https://docs.python.org/3/library/argparse.h
'''
def parseArguments():
	usage = 'python3 server.py port key'
	parser = argparse.ArgumentParser(usage=usage)

	# arguments to be parsed
	parser.add_argument('port', type=int, help='The port will be an integer in range 0-65535.')

	parser.add_argument('key', type=str, help='The key parameter specifies a secret key \
	that must match the client\'s secret key. This key will be also used to derive both \
	the session keys and the initialization vectors.')

	# parse arguments
	args = parser.parse_args()

	# error checking
	port = args.port
	if port not in range(0, 65536):
		print('Error, port must be 0-65535')
		parser.exit('Usage: ' + usage)

	# return arguments to main
	return args

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
	args = parseArguments()
	PORT = args.port
	# initialize socket & listen for connections
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # handles 'port in use'
	s.bind((HOST, PORT))
	s.listen(5)
	print('Server started! Listening on {}:{}...'.format(str(HOST), str(PORT)), file=sys.stderr)

	conn, addr = s.accept()
	print('{}: New connection from: {}'.format(datetime.now().strftime('%H:%M:%S'), str(addr)), file=sys.stderr)
	handleClient('name', conn)

	# close connection
	s.close()

if __name__ == '__main__':
	Main()
