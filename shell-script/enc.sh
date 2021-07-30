#!/bin/bash

openssl rsautl -encrypt -pubin -inkey key.pub -in $1 -out $2
