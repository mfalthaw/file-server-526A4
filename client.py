#!/usr/bin/env python
#client.py

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
CIPHERS = {
	'null': 'null',
	'aes128': 'aes128',
	'aes256': 'aes256',
}
DEBUG = True
CIPHER = 'null'

SECRET_KEY = "0000000000000000"
SESSION_KEY = '0000000000000000'
iv = '0000000000000000'
# nonce = binascii.hexlify(os.urandom(16)).decode()
# print(nonce)
# iv = hashlib.sha256((SECRET_KEY + nonce + "IV").encode())
# SESSION_KEY = hashlib.sha256((SECRET_KEY + nonce + "SK").encode())
# print(iv.hexdigest())

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
Handles sending messages to server
'''
def sendMsg(sock, str):
	if DEBUG:
		print('Sent: ' + str)
	sock.send(encrypt(str.encode('utf-8')))

'''
Handles sending data to server
'''
def sendData(sock, data):
	sock.send(encrypt(data))

'''
Handles receiving messages from server
'''
def recvMsg(sock):
	msg = sock.recv(BUFFER_SIZE)
	msg = decrypt(msg).decode('utf-8')
	if DEBUG:
		print('Recvd: ' + msg)
	return msg

'''
Handles receiving data from server
'''
def recvData(sock):
	data = sock.recv(BUFFER_SIZE)
	return decrypt(data)

'''
Handles uploading files to server
Reads file 31 Bytes at a time; 32-1=31 so padding comes up to 32
'''
def upload(sock, fileName):
	sendMsg(sock, 'upload')
	ack = recvMsg(sock) # needed this to run on lab compute
	sendMsg(sock, fileName)
	ack = recvMsg(sock) # needed this to run on lab compute

	bytesToSend = sys.stdin.buffer.read(BUFFER_SIZE-1)
	sendData(sock, bytesToSend)
	while bytesToSend:
		bytesToSend = sys.stdin.buffer.read(BUFFER_SIZE-1)
		sendData(sock, bytesToSend)

	print('Upload complete!', file=sys.stderr)
	return

'''
Handles downloading files from server
'''
def download(sock, fileName):
	sendMsg(sock, 'download')
	ack = recvMsg(sock) # needed this to run on lab computers
	sendMsg(sock, fileName)
	msg = recvMsg(sock)
	sendMsg(sock, 'ok') # needed this to run on lab computers

	# file found
	if not msg.startswith('Fail!'):
		data = recvData(sock)
		# sendMsg(sock, 'ok') # needed this to run on lab computers
		# print('\n')
		# sys.stdout.buffer.write(data)

		while data:
			sys.stdout.buffer.write(data)
			data = recvData(sock)
			# sys.stdout.buffer.write(data)
		print('\n')
		print('Download complete!', file=sys.stderr)
		sock.close()

	# if file not found
	else:
		print("File doesn't exist!", file=sys.stderr)

'''
Handles parsing arguments
Reference: https://docs.python.org/3/library/argparse.h
'''
def parseArguments():
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

	host, port = args.hostname_port.split(':')
	if int(port) not in range(0, 65536):
		print('Error, port must be 0-65535')
		parser.exit('Usage: ' + usage)

	if args.cipher not in CIPHERS:
		print('Error, cipher must be: aes128, aes256, or null')
		parser.exit('Usage: ' + usage)

	# return arguments to main
	return args

'''
Handles starting the client program
'''
def startClient(socket, command, filename, host, port, cipher, key):
	if DEBUG:
		# confirm connection success with specified arguments
		print('Client started!\n\tCommand: {}\n\tFile Name: {}\n\tHost: {}\n\tPort: {}\
		\n\tCipher: {}\n\tKey: {}'.format(command, filename, host, port, cipher, key))

	# set cipher
	global CIPHER
	CIPHER = CIPHERS[cipher]

	# handle command
	if command == 'read':
		download(socket, filename)
	elif command == 'write':
		upload(socket, filename)
	else:
		print('Unsupported command', file=sys.stderr)


'''
Main
'''
def Main():
	args = parseArguments()
	HOST, PORT = args.hostname_port.split(':')
	# connect to server
	s = socket.socket()
	s.connect((HOST, int(PORT)))
	# start client program
	startClient(s, args.command, args.filename, HOST, PORT, args.cipher, args.key)
	# close socket
	s.close()

if __name__ == '__main__':
	Main()
