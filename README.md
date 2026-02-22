This is a tool that tries to implement as many modern ciphers available for easy testing of decryption. This has been built for the COD Black ops 3 remaining ciphers after the discovery mcrypt was specifically used for a lot of them. 

FULL DISCLAIMER : All of this has been vibe coded, however the implementations of the ciphers them selves are directly pulled from various crypto libs, not the AI.
The app it selfs just acts as a python wrapper, calling several different backends. The orignal implementions can be found from the following repos / locations

CryptoPP
https://github.com/weidai11/cryptopp

PyCryptodome
https://github.com/Legrandin/pycryptodome

MCrypt
https://github.com/winlibs/libmcrypt
https://github.com/php/pecl-encryption-mcrypt

OpenSSL
https://github.com/openssl/openssl/tree/master/crypto

Botan 
https://github.com/randombit/botan

Linux
https://github.com/torvalds/linux/tree/master/crypto

Gladman (AES 1st round candidates)
https://github.com/t-d-k/LibreCrypt/tree/master/src/3rd_party/AES_candidates_1st_round_-_Gladman
