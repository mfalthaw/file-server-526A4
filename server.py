#!/usr/bin/env python
#server.py
# Ref: https://www.youtube.com/watch?v=LJTaPaFGmM4

import string
import socket
import threading
from datetime import datetime
import os

# globals
BUFFER_SIZE = 4096
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
Handles receiving data from client
'''
def recvData(sock):
	return sock.recv(BUFFER_SIZE)

'''
Handle new client
'''
def handleClient(name, sock):
	# sock.
	print("handleClient")

'''
Handles receiving files from client
'''
def receiveFile(name, sock):
	print("receivingFile")

'''
Handles sending files to client
'''
def sendFile(name, sock):
	while True:
		fileName = recvData(sock)
		fileName = fileName.decode()

		print('File Name received: {}'.format(fileName))
		if os.path.isfile(fileName):
			print('Found File')
			fileSize = os.path.getsize(fileName)
			sendMsg(sock, 'Success! File Size: ' + str(fileSize))
			
			userResponse = recvData(sock)
			userResponse = userResponse.decode()
			
			if userResponse.lower().startswith('ok'):
				# start sending file
				with open(fileName, 'rb') as file:
					bytesToSend = file.read(BUFFER_SIZE)
					sendData(sock, bytesToSend)
					
					while bytesToSend.decode() != '':
						bytesToSend = file.read(BUFFER_SIZE)
						sendData(sock, bytesToSend)

					print('file transfer completed!')
			else:
				print('userResponse was: {}'.format(userResponse))
		else:
			# sock.send(("Fail! Can't find: {}".format(fileName)).encode('utf-8'))
			send(sock, "Fail! Can't find: {}".format(fileName))

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
		thread = threading.Thread(target=sendFile, args=("sendFileThread", conn))
		thread.start()

	# close connection
	s.close()

if __name__ == '__main__':
	Main()