#!/bin/bash

# List all password vaults

echo "Listing all password vaults..."
rpawomaster vaults

echo "\nListing password vaults for a specific user..."
rpawomaster vaults -u myuser