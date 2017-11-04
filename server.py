#!/usr/bin/env python
#server.py
# Ref: https://www.youtube.com/watch?v=LJTaPaFGmM4

import string
import socket
import threading
from datetime import datetime
import os

# globals
BUFFER_SIZE = 1024
HOST = '127.0.0.1'
PORT = 8000

'''
Handles sending messages to client
'''
def sendMsg(sock, str):
	sock.send(str.encode('utf-8'))

'''
Handles sending data to client
'''
def sendData(sock, data):
	sock.send(data)

'''
Handles receiving messages from client
'''
def recvMsg(sock):
	return sock.recv(BUFFER_SIZE).decode('utf-8')

'''
Handles receiving data from client
'''
def recvData(sock):
	return sock.recv(BUFFER_SIZE)

'''
Handle new client
'''
def handleClient(name, sock):
	while True:
		task = recvMsg(sock)
		if task.lower() == 'upload':
			receiveFile(sock)
		elif task.lower() == 'download':
			sendFile(sock)
		else:
			sendMsg(sock, "Supported tasks: upload or download")

'''
Handles receiving files from client
'''
def receiveFile(name, sock):
	print("receivingFile")

'''
Handles sending files to client
'''
def sendFile(sock):
	while True:
		fileName = recvMsg(sock)

		print('File Name received: {}'.format(fileName))
		if os.path.isfile(fileName):
			sendMsg(sock, 'File Found!')
			ack = recvMsg(sock) # needed this to run on lab computers
			fileSize = os.path.getsize(fileName)
			sendMsg(sock, str(fileSize))
			ack = recvMsg(sock) # needed this to run on lab computers

			# start sending file
			with open(fileName, 'rb') as file:
				bytesToSend = file.read(BUFFER_SIZE)
				sendData(sock, bytesToSend)
				ack = recvMsg(sock) # needed this to run on lab computers

				totalSent = len(bytesToSend)
				while totalSent < fileSize:
					bytesToSend = file.read(BUFFER_SIZE)
					sendData(sock, bytesToSend)
					totalSent += len(bytesToSend)

				print('File transfer completed!')
				file.close()
				return

		# file not found
		else:
			sendMsg(sock, "Fail! Can't find: {}".format(fileName))
			ack = recvMsg(sock) # needed this to run on lab computers
			return

	# close connection
	sock.close()


def Main():
	# initilize socket & listen for connections
	s = socket.socket()
	s.bind((HOST, PORT))
	s.listen(5)
	print('Server started! Listening on {}:{}...'.format(str(HOST), str(PORT)))

	while True:
		conn, addr = s.accept()
		print('{}: New connection from: {}'.format(datetime.now().strftime('%H:%M:%S'), str(addr)))
		handleClient('name', conn)


	# close connection
	s.close()

if __name__ == '__main__':
	Main()
