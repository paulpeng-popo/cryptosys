#!/bin/bash

# Check openssl is installed
if ! command -v openssl &> /dev/null
then
	    sudo apt install openssl -y
fi

KEY_LEN=2048
KEY_NAME=key

# Gen pri_key
openssl genrsa -out ${KEY_NAME}.pem ${KEY_LEN}

# Gen pub_key
openssl rsa -in ${KEY_NAME}.pem -pubout > ${KEY_NAME}.pub
