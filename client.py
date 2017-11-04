#!/usr/bin/env python
#client.py

import string
import socket
import argparse

# globals
BUFFER_SIZE = 1024
# HOST = '127.0.0.1'
# PORT = 8000
CIPHERS = [
	'null',
	'aes128',
	'aes256'
]

'''
Handles sending messages to server
'''
def sendMsg(sock, str):
	sock.send(str.encode('utf-8'))

'''
Handles sending data to server
'''
def sendData(sock, data):
	sock.send(data)

'''
Handles receiving messages from server
'''
def recvMsg(sock):
	return sock.recv(BUFFER_SIZE).decode('utf-8')

'''
Handles receiving data from server
'''
def recvData(sock):
	return sock.recv(BUFFER_SIZE)

'''
Handles uploading files to server
'''
def upload(s):
	print('Hey! you want to upload')

'''
Handles downloading files from server
'''
def download(sock):
	fileName = input("Filename?\n> ")
	sendMsg(sock, fileName)
	msg = recvMsg(sock)
	sendMsg(sock, 'ok') # needed this to run on lab computers

	# file found
	if not msg.startswith('Fail!'):
		fileSize = int(recvMsg(sock))
		sendMsg(sock, 'ok') # needed this to run on lab computers
		file = open('DOWNLOADED_' + fileName, 'wb')
		data = recvData(sock)
		sendMsg(sock, 'ok') # needed this to run on lab computers
		file.write(data)

		totalRecvd = len(data)
		while totalRecvd < fileSize:
			data = recvData(sock)
			file.write(data)
			totalRecvd += len(data)
			print("{0:.2f} %".format((totalRecvd/float(fileSize)) * 100))

		file.close()
		print("Download complete!")

	# if file not found
	else:
		print("File doesn't exist!")

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
def startClient(command, filename, host, port, cipher, key):
	# confirm connection success with specified arguments
	print('Client started!\n\tCommand: {}\n\tFile Name: {}\n\tHost: {}\n\tPort: {}\
	\n\tCipher: {}\n\tKey: {}'.format(command, filename, host, port, cipher, key))


'''
Main
'''
def Main():
	args = parseArguments()
	HOST, PORT = args.hostname_port.split(':')

	# connect to server
	s = socket.socket()
	s.connect((HOST, int(PORT)))

	# start client progtam
	startClient(args.command, args.filename, HOST, PORT, args.cipher, args.key)

	# close socket
	s.close()

if __name__ == '__main__':
	Main()
