#!/bin/bash

pip3 install -r requirements.txt
sudo mv Dark-Shell.py /usr/local/bin/Dark-Shell
sudo chmod +x /usr/local/bin/Dark-Shell
sudo rm -rf *

echo "Please Restart Your Terminal!!!"
