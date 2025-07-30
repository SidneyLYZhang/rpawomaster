#!/bin/bash

# Test password strength and properties

echo "Testing password strength..."
rpawomaster testpass mypassword123

echo "\nTesting if password is URL-safe..."
rpawomaster testpass mypassword123 -s

echo "\nTesting for visually confusing characters..."
rpawomaster testpass mypassword123 -c

echo "\nTesting all properties of a password..."
rpawomaster testpass mypassword123 -s -c