#!/bin/bash

# Add a password to the vault

echo "Adding a password to the vault (interactive mode)..."
rpawomaster add

echo "\nAdding a password for a specific user..."
rpawomaster add -u myuser

echo "\nAdding a password to a specific vault..."
rpawomaster add -v MyVault

echo "\nAdding a password for a specific user and vault..."
rpawomaster add -u myuser -v MyVault