#!/usr/bin/env python
#client.py

import string
import socket
import argparse

# globals
BUFFER_SIZE = 1024
HOST = '127.0.0.1'
PORT = 8000


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

	parser.add_argument('hostname:port', type=str, help='The hostname:port argument \
	specifies the address of the server, and the port on which the server is listening. \
	The hostname can be specified as a domain name or an IPv4 address. \
	he port will be an integer in range 0-65535.')

	parser.add_argument('cipher', type=str, help='The cipher argument specifies which \
	cipher is to be used for encrypting the communication with the server. Valid values \
	are aes256, aes128 and null.')

	parser.add_argument('key', type=str, help='The key parameter specifies a secret key \
	that must match the server’s secret key. This key will be also used to derive both \
	the session keys and the initialization vectors.')

	# parse and return arguments to main
	args = parser.parse_args()
	return args

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
Prompt the user for download or upload
'''
def promptForTask():
	task = input('What would you like to do? Upload or Download?\n> ')
	return task

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
Main
'''
def Main():
	args = parseArguments()
	HOST, PORT = args.split(':')

	s = socket.socket()
	s.connect((HOST, PORT))

	while True:
		task = promptForTask()
		if task == 'upload':
			sendMsg(s, 'upload')
			upload(s)
		elif task == 'download':
			sendMsg(s, 'download')
			download(s)

	# close socket
	s.close()

if __name__ == '__main__':
	Main()
