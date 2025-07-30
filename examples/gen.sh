#!/bin/bash

# Generate a new password

echo "Generating a random password with default settings..."
rpawomaster gen random

echo "\nGenerating a random password with custom length..."
rpawomaster gen random -l 20

echo "\nGenerating a random password without special characters..."
rpawomaster gen random --no-special

echo "\nGenerating a memorable password with default settings..."
rpawomaster gen memorable

echo "\nGenerating a memorable password with 6 words..."
rpawomaster gen memorable -w 6

echo "\nGenerating a memorable password with underscore separator..."
rpawomaster gen memorable -s _