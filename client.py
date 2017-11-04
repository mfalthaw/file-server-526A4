#!/usr/bin/env python
#client.py

import string
import socket

# globals
BUFFER_SIZE = 4096
HOST = '127.0.0.1'
PORT = 8000

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
	return sock.recv(BUFFER_SIZE).decode()

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

	# file found
	if not msg.startswith('Fail!'):
		fileSize = int(recvMsg(sock))
		file = open('DOWNLOADED_' + fileName, 'wb')
		data = recvData(sock)
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