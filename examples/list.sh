#!/bin/bash

# List all existing passwords

echo "Listing all passwords..."
rpawomaster list

echo "\nListing passwords for a specific user..."
rpawomaster list -u myuser

echo "\nListing passwords from a specific vault..."
rpawomaster list -v MyVault

echo "\nListing passwords for a specific user and vault..."
rpawomaster list -u myuser -v MyVault