#!/bin/bash

openssl rsautl -decrypt -inkey key.pem -in $1 -out $2
