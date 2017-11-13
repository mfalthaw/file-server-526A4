import re

filename = 'time_tests.txt'
pattern  = ''
lines = None
temp = []

with open(filename, 'r') as file:
   lines = file.readlines()
   file.close()

for line in lines:
    line = line.strip()
    if line.startswith('size'):
        if '1024' in line:
            line = line.replace('1024', '1KB')
        elif '1048576' in line:
            line = line.replace('1048576', '1MB')
        elif '1073741824' in line:
            line = line.replace('1073741824', '1GB')    
        print(line)
        continue
    elif line.startswith('real'):
        min = 0
        _, time = line.split('\t')
        if '1m' in time:
            min = 60
        time = time.replace('m', '')
        time = time.replace('s', '')
        temp.append(float(float(time)+min))
        if len(temp) == 10:
            temp = sorted(temp)
            avg = float(temp[4]+temp[5])/float(2)
            print(str(avg))
            temp = []