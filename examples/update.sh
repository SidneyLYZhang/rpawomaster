#!/bin/bash

# Update an existing password

echo "Updating a specific password..."
rpawomaster update -p mypassword

echo "\nUpdating a specific password for a user..."
rpawomaster update -p mypassword -u myuser

echo "\nUpdating a specific password in a vault..."
rpawomaster update -p mypassword -v MyVault

echo "\nUpdating all expired passwords..."
rpawomaster update -a true

echo "\nUpdating all expired passwords for a user..."
rpawomaster update -a true -u myuser