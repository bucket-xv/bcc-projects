#!/bin/bash

# Install Go
LATEST_GO_VERSION=$(curl -s https://go.dev/VERSION?m=text | head -n 1)
echo "Latest Go version: $LATEST_GO_VERSION"
wget https://go.dev/dl/$LATEST_GO_VERSION.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf $LATEST_GO_VERSION.linux-amd64.tar.gz
rm $LATEST_GO_VERSION.linux-amd64.tar.gz
PROFILE_PATH=~/.bashrc
echo 'export PATH=$PATH:/usr/local/go/bin' >> $PROFILE_PATH
source $PROFILE_PATH
echo 'export GOPATH=$HOME/go' >> $PROFILE_PATH
echo 'export PATH=$PATH:$GOPATH/bin' >> $PROFILE_PATH
source $PROFILE_PATH

# Install Protobuf
sudo apt update -y
sudo apt install -y protobuf-compiler

# Clone the repository
git clone https://github.com/appnet-org/arpc.git
cd arpc

# Install the dependencies
go mod tidy

