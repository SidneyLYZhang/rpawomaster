#!/bin/bash

# Export password vault

echo "Exporting password vault for a user..."
rpawomaster export myuser

echo "\nExporting password vault for a user to a specific path..."
rpawomaster export myuser -p /path/to/export/

echo "\nExporting a specific vault for a user..."
rpawomaster export myuser -v MyVault

echo "\nExporting a specific vault for a user to a specific path..."
rpawomaster export myuser -p /path/to/export/ -v MyVault