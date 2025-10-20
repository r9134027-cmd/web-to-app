#!/bin/bash

echo "===================================================================="
echo "   Advanced Domain Reconnaissance Desktop Application"
echo "===================================================================="
echo ""
echo "Starting application..."
echo ""

python3 run.py

if [ $? -ne 0 ]; then
    echo ""
    echo "Error: Failed to start application"
    echo ""
    echo "Please ensure Python 3.8+ is installed"
    echo "Try: python3 --version"
    echo ""
    read -p "Press Enter to exit..."
fi
