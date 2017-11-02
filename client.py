#!/usr/bin/env python
#client.py

import string
import socket

# globals
BUFFER_SIZE = 4096
HOST = '127.0.0.1'
PORT = 8000

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
def download(s):
	fileName = input("Filename?\n> ")
	if fileName != 'q':
		s.send(fileName.encode('utf-8'))
		
		data = s.recv(BUFFER_SIZE)
		data = data.decode()

		if data.startswith('Success!'):
			fileSize = int(data[20:])
			msg = input("File Found! " + str(fileSize) + " Bytes. Download? (Y/N)\n> ")
			if msg.lower().startswith('y'):
				s.send('OK'.encode('utf-8'))
				file = open('DOWNLOADED_' + fileName, 'wb')
				
				data = s.recv(BUFFER_SIZE)
				totalRecvd = len(data)
				
				file.write(data)
				while totalRecvd < fileSize:
					data = s.recv(BUFFER_SIZE)
					totalRecvd += len(data)
					file.write(data)
					print("{0:.2f} %".format((totalRecvd/float(fileSize)) * 100))

				print("Download complete!")
				# if not success
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
		if task.lower().startswith('u'):
			upload(s)
		elif task.lower().startswith('d'):
			print('Hey! you want to download')
			download(s)

	# close socket
	s.close()



if __name__ == '__main__':
	Main()