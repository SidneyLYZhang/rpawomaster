#!/bin/bash

# Initialize a new password vault
# This will prompt for username and core password if not provided

echo "Initializing a new password vault..."
rpawomaster init

echo "\nInitializing a new password vault with a specific user..."
rpawomaster init -u myuser

echo "\nImporting a password vault from a file..."
rpawomaster init -i /path/to/import/username.tgz