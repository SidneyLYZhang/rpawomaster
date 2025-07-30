#!/bin/bash

# Delete an existing password

echo "Deleting a password..."
rpawomaster delete mypassword

echo "\nDeleting a password for a specific user..."
rpawomaster delete mypassword -u myuser

echo "\nDeleting a password from a specific vault..."
rpawomaster delete mypassword -v MyVault

echo "\nDeleting a password for a specific user and vault..."
rpawomaster delete mypassword -u myuser -v MyVault