brew install openssl
brew install swig
brew install sleuthkit

# see https://gitlab.com/m2crypto/m2crypto/-/blob/master/INSTALL.rst#id4
LDFLAGS="-L$(brew --prefix openssl)/lib" \
CFLAGS="-I$(brew --prefix openssl)/include" \
SWIG_FEATURES="-I$(brew --prefix openssl)/include" \
pip install m2crypto==0.35.2

LDFLAGS="-L$(brew --prefix openssl)/lib" \
CFLAGS="-I$(brew --prefix openssl)/include" \
SWIG_FEATURES="-I$(brew --prefix openssl)/include" \
pip install scrypt==0.8.13
