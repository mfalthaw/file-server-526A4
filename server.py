#!/usr/bin/env python
#server.py
# Ref: https://www.youtube.com/watch?v=LJTaPaFGmM4

import string
import socket
import threading
import os

# globals
BUFFER_SIZE = 4096
HOST = '127.0.0.1'
PORT = 8000

def retrieve(name, sock):
	fileName = sock.recv(BUFFER_SIZE)
	fileName = fileName.decode()

	print('File Name recieved: {}'.format(fileName))
	if os.path.isfile(fileName):
		print('Found File')
		fileSize = os.path.getsize(fileName)
		sock.send(('Success! File Size: ' + str(fileSize)).encode('utf-8'))
		
		userResponse = sock.recv(BUFFER_SIZE)
		userResponse = userResponse.decode()
		
		if userResponse.lower().startswith('ok'):
			# start sending file
			with open(fileName, 'rb') as file:
				bytesToSend = file.read(BUFFER_SIZE)
				sock.send(bytesToSend)
				
				while bytesToSend != '':
					bytesToSend = file.read(BUFFER_SIZE)
					sock.send(bytesToSend)
		else:
			print('userResponse was: {}'.format(userResponse))
	else:
		sock.send(("Fail! Can't find: {}".format(fileName)).encode('utf-8'))

	# close connection
	sock.close()


def Main():
	# initilize socket & listen for connections
	s = socket.socket()
	s.bind((HOST, PORT))
	s.listen(5)
	print('Server started...\nListening on {}:{}'.format(str(HOST), str(PORT)))

	while True:
		conn, addr = s.accept()
		print('Client connected...\nAddress: {}'.format(str(addr)))
		thread = threading.Thread(target=retrieve, args=("retrieveThread", conn))
		thread.start()

	# close connection
	s.close()

if __name__ == '__main__':
	Main()