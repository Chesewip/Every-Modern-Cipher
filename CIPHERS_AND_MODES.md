# Supported Ciphers & Modes

MCRYPT supports **77 ciphers** across 4 engines and **24 modes** of operation.

---

## Engines

| Engine | Language | Ciphers | Notes |
|--------|----------|---------|-------|
| mcrypt (libmcrypt) | PHP | 19 | Legacy PHP extension, bundled portable PHP 7.1 |
| OpenSSL | PHP | 8 | Ciphers not available in mcrypt |
| PyCryptodome | Python | 11 | Additional ciphers + stream ciphers |
| Crypto++ / Botan / Gladman / Standalone | C++ | 43 | Pre-built `cryptopp_brute.exe` |

---

## Block Ciphers

### mcrypt (PHP) — 16 block ciphers

| Cipher | Block Size | Key Sizes (bytes) |
|--------|-----------|-------------------|
| Blowfish | 8 | 1–56 (variable) |
| Twofish | 16 | 16, 24, 32 |
| DES | 8 | 8 |
| 3DES (Triple DES) | 8 | 24 |
| SAFER+ | 16 | 16, 24, 32 |
| LOKI97 | 16 | 16, 24, 32 |
| GOST | 8 | 32 |
| RC2 | 8 | 1–128 (variable) |
| Rijndael-128 (AES) | 16 | 16, 24, 32 |
| Rijndael-192 | 24 | 16, 24, 32 |
| Rijndael-256 | 32 | 16, 24, 32 |
| Serpent | 16 | 16, 24, 32 |
| CAST-128 | 8 | 5–16 (variable) |
| CAST-256 | 16 | 16, 24, 32 |
| XTEA | 8 | 16 |
| Blowfish-compat | 8 | 1–56 (variable) |

### OpenSSL (PHP) — 6 block ciphers

| Cipher | Block Size | Key Sizes (bytes) | Modes |
|--------|-----------|-------------------|-------|
| Camellia-128 | 16 | 16 | ECB, CBC, CFB, OFB |
| Camellia-192 | 16 | 24 | ECB, CBC, CFB, OFB |
| Camellia-256 | 16 | 32 | ECB, CBC, CFB, OFB |
| SEED | 16 | 16 | ECB, CBC, CFB, OFB |
| DESX | 8 | 24 | CBC only |
| AES-128/192/256 | 16 | 16, 24, 32 | CTR only (supplements mcrypt Rijndael) |

### PyCryptodome (Python) — 8 block ciphers

| Cipher | Block Size | Key Sizes (bytes) |
|--------|-----------|-------------------|
| AES-128-PC | 16 | 16 |
| AES-192-PC | 16 | 24 |
| AES-256-PC | 16 | 32 |
| DES-PC | 8 | 8 |
| 3DES-PC | 8 | 24 |
| Blowfish-PC | 8 | 4–56 (variable) |
| CAST5-PC | 8 | 5–16 (variable) |
| RC2-PC | 8 | 5–128 (variable) |

### Crypto++ (C++) — 30 block ciphers

| Cipher | Block Size | Key Sizes (bytes) |
|--------|-----------|-------------------|
| IDEA | 8 | 16 |
| RC5 | 8 | 1–255 (variable) |
| RC6 | 16 | 16, 24, 32 |
| MARS | 16 | 16–56 (variable) |
| Skipjack | 8 | 10 |
| 3-Way | 12 | 12 |
| SAFER-SK64 | 8 | 8 |
| SAFER-SK128 | 8 | 16 |
| ARIA | 16 | 16, 24, 32 |
| SM4 | 16 | 16 |
| LEA | 16 | 16, 24, 32 |
| HIGHT | 8 | 16 |
| TEA | 8 | 16 |
| Square | 16 | 16 |
| SHARK | 8 | 16 |
| SHACAL-2 | 32 | 16–64 (variable) |
| SIMON-64 | 8 | 12, 16 |
| SIMON-128 | 16 | 16, 24, 32 |
| SPECK-64 | 8 | 12, 16 |
| SPECK-128 | 16 | 16, 24, 32 |
| SIMECK-32 | 4 | 8 |
| SIMECK-64 | 8 | 16 |
| CHAM-64 | 8 | 16 |
| CHAM-128 | 16 | 16, 32 |
| Kalyna-128 | 16 | 16, 32 |
| Kalyna-256 | 32 | 32, 64 |
| Kalyna-512 | 64 | 64 |
| Threefish-256 | 32 | 32 |
| Threefish-512 | 64 | 64 |
| Threefish-1024 | 128 | 128 |

### Gladman AES Round 1 Candidates (C++) — 6 block ciphers

| Cipher | Block Size | Key Sizes (bytes) |
|--------|-----------|-------------------|
| CRYPTON | 16 | 16, 24, 32 |
| DFC | 16 | 16, 24, 32 |
| E2 | 16 | 16, 24, 32 |
| FROG | 16 | 5–125 (variable) |
| MAGENTA | 16 | 16, 24, 32 |
| HPC | 16 | 16, 24, 32 |

### Botan 2.x (C++) — 3 block ciphers

| Cipher | Block Size | Key Sizes (bytes) |
|--------|-----------|-------------------|
| MISTY1 | 8 | 16 |
| KASUMI | 8 | 16 |
| Noekeon | 16 | 16 |

### Standalone (C++) — 4 block ciphers

| Cipher | Block Size | Key Sizes (bytes) |
|--------|-----------|-------------------|
| CLEFIA | 16 | 16, 24, 32 |
| Anubis | 16 | 16–40 (variable) |
| Khazad | 8 | 16 |
| Kuznyechik (GOST R 34.12-2015) | 16 | 32 |

---

## Stream Ciphers

### mcrypt (PHP) — 3 stream ciphers

| Cipher | Key Sizes (bytes) | IV Size |
|--------|-------------------|---------|
| Arcfour (RC4) | 1–256 (variable) | — |
| WAKE | 32 | — |
| Enigma | 13 | — |

### PyCryptodome (Python) — 3 stream ciphers

| Cipher | Key Sizes (bytes) | Nonce Size |
|--------|-------------------|------------|
| Salsa20 | 16, 32 | 8 |
| ChaCha20 | 32 | 8 |
| RC4-PC | 1–256 (variable) | — |

### Crypto++ (C++) — 7 stream ciphers

| Cipher | Key Sizes (bytes) | IV/Nonce Size |
|--------|-------------------|---------------|
| Sosemanuk | 1–32 (variable) | 16 |
| Rabbit | 16 | 8 |
| HC-128 | 16 | 16 |
| HC-256 | 32 | 32 |
| Panama | 32 | 32 |
| SEAL | 20 | 4 |
| XSalsa20 | 32 | 24 |

---

## Modes of Operation

### Block Cipher Modes

| Mode | Description | Available In |
|------|-------------|-------------|
| ECB | Electronic Codebook | All engines |
| CBC | Cipher Block Chaining | All engines |
| CFB | Cipher Feedback (8-bit) | All engines |
| OFB | Output Feedback (8-bit) | mcrypt only |
| NOFB | Output Feedback (full-block) | All engines |
| NCFB | Cipher Feedback (full-block) | All engines |
| CTR | Counter | All engines |

### CFB Feedback Size Variants (Crypto++ engine only)

| Mode | Feedback Size |
|------|--------------|
| CFB-8 | 8-bit (1 byte) |
| CFB-16 | 16-bit (2 bytes) |
| CFB-24 | 24-bit (3 bytes) |
| CFB-32 | 32-bit (4 bytes) |
| CFB-40 | 40-bit (5 bytes) |
| CFB-48 | 48-bit (6 bytes) |
| CFB-56 | 56-bit (7 bytes) |
| CFB-64 | 64-bit (8 bytes) |
| CFB-72 | 72-bit (9 bytes) |
| CFB-80 | 80-bit (10 bytes) |
| CFB-88 | 88-bit (11 bytes) |
| CFB-96 | 96-bit (12 bytes) |
| CFB-104 | 104-bit (13 bytes) |
| CFB-112 | 112-bit (14 bytes) |
| CFB-120 | 120-bit (15 bytes) |
| CFB-128 | 128-bit (16 bytes) |

> CFB-N modes are automatically pruned when the feedback size exceeds the cipher's block size.

### Stream Cipher Mode

| Mode | Description | Available In |
|------|-------------|-------------|
| Stream | Native stream cipher operation | All engines (stream ciphers only) |

---

## Cipher Count by Engine

| Engine | Block | Stream | Total |
|--------|-------|--------|-------|
| mcrypt | 16 | 3 | 19 |
| OpenSSL | 8 | 0 | 8 |
| PyCryptodome | 8 | 3 | 11 |
| Crypto++ | 30 | 7 | 37 |
| Gladman | 6 | 0 | 6 |
| Botan | 3 | 0 | 3 |
| Standalone | 4 | 0 | 4 |
| **Total** | **75** | **13** | **88** |

> Some ciphers appear in multiple engines (e.g., AES, DES, Blowfish, RC4). Unique cipher algorithms: **~77**.
