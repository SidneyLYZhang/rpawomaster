#!/bin/bash

# Search passwords in the vault

echo "Searching for passwords containing 'github'..."
rpawomaster search github

echo "\nSearching for passwords containing 'github' for a specific user..."
rpawomaster search github -u myuser

echo "\nSearching for passwords containing 'github' in a specific vault..."
rpawomaster search github -v MyVault

echo "\nSearching for passwords with exact match..."
rpawomaster search github --exact true

echo "\nSearching for passwords with exact match for a user and vault..."
rpawomaster search github -u myuser -v MyVault --exact true