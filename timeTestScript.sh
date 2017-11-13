#!/bin/bash

# 3 Ciphers "null", "aes128", "aes256"
# Upload and download for each one
# Run with 3 sizes: 1KB, 1 MB, 1 GB

# Seed
SEED=6

function run_test {
    echo "size: $size cipher: $cipher command: $command" >> time_tests.txt

    for i in {1..10}
    do
        python3 server.py 8000 myKey &
        sleep 1
        if [ "$command" == "write" ]; then
            result="$((time ./bgen.py $size $SEED | python3 client.py $command $filename localhost:8000 $cipher myKey < $filename) 2>&1)"
        elif [ "$command" == "read" ]; then
            result="$((time python3 client.py $command $filename localhost:8000 $cipher myKey | shasum -a 256) 2>&1)"
        else
            echo "Invalid command"
            exit
        fi
        echo "$result" | tail -3 >> time_tests.txt
        echo >> time_tests.txt
    sleep 1
    done
}

# First run of using 1KB
size=1024
cipher="null"
command="write"
filename="1KB.bin"
run_test

command="read"
run_test

cipher="aes128"
command="write"
run_test

command="read"
run_test

cipher="aes256"
command="write"
run_test

command="read"
run_test

# Second run of using 1MB
let size=1024**2
cipher="null"
command="write"
filename="1MB.bin"
run_test

command="read"
run_test

cipher="aes128"
command="write"
run_test

command="read"
run_test

cipher="aes256"
command="write"
run_test

command="read"
run_test

# Second run of using 1GB
let size=1024**3
cipher="null"
command="write"
filename="1GB.bin"
run_test

command="read"
run_test

cipher="aes128"
command="write"
run_test

command="read"
run_test

cipher="aes256"
command="write"
run_test

command="read"
run_test
