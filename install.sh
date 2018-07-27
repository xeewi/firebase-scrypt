echo '  [x] Install SLL dev dependency'
sudo apt install libssl-dev 

echo '  [x] Install automake'
sudo apt install automake

echo '  [x] Clone firebase Scrypt repo'
git clone https://github.com/firebase/scrypt.git

echo '  [x] Build Scrypt'
cd scrypt/
autoreconf -i
./configure
make