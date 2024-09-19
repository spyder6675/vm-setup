#!/bin/bash

# Check for apt updates
echo "Checking if apt can update the package repository..."
sudo apt update > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "APT is working: Package repository updated successfully."
else
    echo "APT update failed: Unable to update package repository."
    exit 1
fi

# Test cloning a GitHub repository
echo "Checking if Git can clone repositories..."
TEST_REPO="https://github.com/digininja/CeWL.git"
CLONE_DIR="test_clone"
git clone "$TEST_REPO" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Git is working: Repository cloned successfully."
    rm -rf "CeWL"
else
    echo "Git clone failed: Unable to clone repository."
    exit 1
fi

# Test installing a Go package
echo "Checking if Go can install packages..."
GO_PACKAGE="github.com/ropnop/kerbrute@latest"
go install "$GO_PACKAGE" > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "Go is working: Go package installed successfully."
else
    echo "Go install failed: Unable to install Go package."
    exit 1
fi

echo "All checks passed!"
