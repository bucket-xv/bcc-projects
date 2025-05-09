sudo apt update -y
sudo apt install -y python-is-python3 cmake   
sudo apt install -y python3-pip

# Prerequisites for Focal (20.04.1 LTS)
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev arping iperf

# Prerequisites for Jammy (22.04)
# sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
#   libllvm14 llvm-14-dev libclang-14-dev python3 zlib1g-dev libelf-dev libfl-dev python3-setuptools \
#   liblzma-dev libdebuginfod-dev arping netperf iperf

# Compile and install
git clone https://github.com/iovisor/bcc.git
mkdir bcc/build; cd bcc/build
cmake ..
make
sudo make install
cmake -DPYTHON_CMD=python3 .. # build python3 binding
pushd src/python/
make
sudo make install
popd

# copy to python3/dist-packages
sudo cp -r ~/bcc/build/src/python/bcc-python3/bcc/* /usr/lib/python3/dist-packages/bcc/