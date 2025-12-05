#!/bin/bash
set -e

echo "🔍 Updating package lists..."
sudo apt update

echo "📦 Installing prerequisites..."
sudo apt install -y software-properties-common curl

echo "➕ Adding deadsnakes PPA for newer Python versions..."
sudo add-apt-repository -y ppa:deadsnakes/ppa

echo "🔄 Updating package lists again..."
sudo apt update

echo "🐍 Installing Python 3.11 and tools..."
sudo apt install -y python3.11 python3.11-venv python3.11-dev python3.11-distutils

echo "🔧 Ensuring pip for Python 3.11 is installed..."
curl -sS https://bootstrap.pypa.io/get-pip.py -o get-pip.py
sudo python3.11 get-pip.py
rm get-pip.py

echo "📌 Setting python3.11 as an alternative..."
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 2

echo "🎉 Done!"
echo "Python version now installed:"
python3.11 --version
