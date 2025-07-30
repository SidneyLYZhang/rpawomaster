#!/bin/bash

# Encrypt or decrypt files/directories

echo "Encrypting a file..."
rpawomaster crypt en -s myuser /path/to/source/file.txt /path/to/target/file.txt.esz

echo "\nDecrypting a file..."
rpawomaster crypt de -s myuser /path/to/source/file.txt.esz /path/to/target/file.txt

echo "\nEncrypting a directory..."
rpawomaster crypt en -s myuser /path/to/source/dir /path/to/target/dir.esz

echo "\nDecrypting a directory..."
rpawomaster crypt de -s myuser /path/to/source/dir.esz /path/to/target/dir