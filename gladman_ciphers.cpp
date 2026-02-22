/**
 * Gladman AES Round 1 Cipher Adapter
 *
 * Provides DecryptFunc-compatible wrappers for 6 Gladman block ciphers:
 * CRYPTON, DFC, E2, FROG, MAGENTA, HPC
 *
 * All are 128-bit block ciphers. Mode implementations (ECB/CBC/CFB/OFB/CTR)
 * are done manually since these are plain C functions, not Crypto++ classes.
 */

#include "gladman_ciphers.h"
#include "gladman/std_defs.h"

#include <cstring>
#include <string>
#include <algorithm>

// ---------------------------------------------------------------------------
// Forward declarations of cipher functions from wrapper translation units
// ---------------------------------------------------------------------------

namespace gladman_crypton {
    u4byte* set_key(const u4byte in_key[], const u4byte key_len);
    void encrypt(const u4byte in_blk[4], u4byte out_blk[4]);
    void decrypt(const u4byte in_blk[4], u4byte out_blk[4]);
}

namespace gladman_dfc {
    u4byte* set_key(const u4byte in_key[], const u4byte key_len);
    void encrypt(const u4byte in_blk[4], u4byte out_blk[4]);
    void decrypt(const u4byte in_blk[4], u4byte out_blk[4]);
}

namespace gladman_e2 {
    u4byte* set_key(const u4byte in_key[], const u4byte key_len);
    void encrypt(const u4byte in_blk[4], u4byte out_blk[4]);
    void decrypt(const u4byte in_blk[4], u4byte out_blk[4]);
}

namespace gladman_frog {
    u4byte* set_key(const u4byte in_key[], const u4byte key_len);
    void encrypt(const u4byte in_blk[4], u4byte out_blk[4]);
    void decrypt(const u4byte in_blk[4], u4byte out_blk[4]);
}

namespace gladman_magenta {
    u4byte* set_key(const u4byte in_key[], const u4byte key_len);
    void encrypt(const u4byte in_blk[4], u4byte out_blk[4]);
    void decrypt(const u4byte in_blk[4], u4byte out_blk[4]);
}

namespace gladman_hpc {
    u4byte* set_key(const u4byte in_key[], const u4byte key_len);
    void encrypt(const u4byte in_blk[4], u4byte out_blk[4]);
    void decrypt(const u4byte in_blk[4], u4byte out_blk[4]);
}

// ---------------------------------------------------------------------------
// Cipher descriptor
// ---------------------------------------------------------------------------

struct GladmanCipher {
    using SetKeyFn = u4byte*(*)(const u4byte[], const u4byte);
    using BlockFn  = void(*)(const u4byte[4], u4byte[4]);

    const char* name;
    SetKeyFn    set_key;
    BlockFn     encrypt_block;
    BlockFn     decrypt_block;
};

static const GladmanCipher GLADMAN_CIPHERS[] = {
    {"crypton", gladman_crypton::set_key, gladman_crypton::encrypt, gladman_crypton::decrypt},
    {"dfc",     gladman_dfc::set_key,     gladman_dfc::encrypt,     gladman_dfc::decrypt},
    {"e2",      gladman_e2::set_key,      gladman_e2::encrypt,      gladman_e2::decrypt},
    {"frog",    gladman_frog::set_key,    gladman_frog::encrypt,    gladman_frog::decrypt},
    {"magenta", gladman_magenta::set_key, gladman_magenta::encrypt, gladman_magenta::decrypt},
    {"hpc",     gladman_hpc::set_key,     gladman_hpc::encrypt,     gladman_hpc::decrypt},
};

static constexpr size_t NUM_GLADMAN = sizeof(GLADMAN_CIPHERS) / sizeof(GLADMAN_CIPHERS[0]);
static constexpr size_t BS = 16;  // all Gladman ciphers are 128-bit block

// ---------------------------------------------------------------------------
// XOR helper
// ---------------------------------------------------------------------------

static void xor_blocks(const unsigned char* a, const unsigned char* b,
                       unsigned char* out, size_t len) {
    for (size_t i = 0; i < len; i++)
        out[i] = a[i] ^ b[i];
}

// ---------------------------------------------------------------------------
// Counter increment (big-endian, rightmost byte first)
// ---------------------------------------------------------------------------

static void increment_counter(unsigned char* ctr, size_t len) {
    for (size_t i = len; i > 0; --i) {
        if (++ctr[i - 1] != 0) break;
    }
}

// ---------------------------------------------------------------------------
// Parse cfb-N mode string (duplicated from cryptopp_brute.cpp)
// ---------------------------------------------------------------------------

static int parse_cfb_feedback(const std::string& mode) {
    if (mode.size() > 4 && mode.substr(0, 4) == "cfb-") {
        try {
            int bits = std::stoi(mode.substr(4));
            if (bits >= 8 && bits <= 128 && bits % 8 == 0)
                return bits / 8;
        } catch (...) {}
    }
    return 0;
}

// ---------------------------------------------------------------------------
// Generic decryption using manual mode implementations
// ---------------------------------------------------------------------------

static bool gladman_try_decrypt(
    const GladmanCipher& cipher,
    const std::string& mode,
    const std::string& ct,
    const std::string& key,
    const std::string& iv,
    std::string& plaintext)
{
    try {
        size_t ct_len = ct.size();
        if (ct_len == 0) return false;

        // Set key: convert bytes to u4byte array, key_len in BITS
        u4byte key_words[64];
        std::memset(key_words, 0, sizeof(key_words));
        size_t key_bytes = std::min(key.size(), (size_t)256);
        std::memcpy(key_words, key.data(), key_bytes);
        u4byte key_bits = (u4byte)(key_bytes * 8);
        cipher.set_key(key_words, key_bits);

        // Prepare IV as bytes
        unsigned char iv_buf[BS];
        std::memset(iv_buf, 0, BS);
        if (!iv.empty()) {
            size_t iv_copy = std::min(iv.size(), (size_t)BS);
            std::memcpy(iv_buf, iv.data(), iv_copy);
        }

        const auto* ct_data = reinterpret_cast<const unsigned char*>(ct.data());

        // ── ECB ──
        if (mode == "ecb") {
            if (ct_len % BS != 0) return false;
            plaintext.resize(ct_len);
            auto* pt_data = reinterpret_cast<unsigned char*>(&plaintext[0]);
            for (size_t i = 0; i < ct_len; i += BS) {
                cipher.decrypt_block(
                    reinterpret_cast<const u4byte*>(ct_data + i),
                    reinterpret_cast<u4byte*>(pt_data + i));
            }
            return true;
        }

        // ── CBC ──
        if (mode == "cbc") {
            if (ct_len % BS != 0) return false;
            plaintext.resize(ct_len);
            auto* pt_data = reinterpret_cast<unsigned char*>(&plaintext[0]);
            const unsigned char* prev = iv_buf;
            u4byte tmp[4];
            for (size_t i = 0; i < ct_len; i += BS) {
                cipher.decrypt_block(
                    reinterpret_cast<const u4byte*>(ct_data + i), tmp);
                xor_blocks(reinterpret_cast<const unsigned char*>(tmp),
                           prev, pt_data + i, BS);
                prev = ct_data + i;
            }
            return true;
        }

        // ── CFB (variable feedback size) ──
        // "cfb" = 1-byte feedback, "ncfb" = full-block, "cfb-N" = N/8 bytes
        int fb = 0;
        if (mode == "cfb") {
            fb = 1;
        } else if (mode == "ncfb") {
            fb = (int)BS;
        } else {
            fb = parse_cfb_feedback(mode);
        }
        if (fb > 0) {
            if ((size_t)fb > BS) return false;
            plaintext.resize(ct_len);
            auto* pt_data = reinterpret_cast<unsigned char*>(&plaintext[0]);
            unsigned char shift_reg[BS];
            std::memcpy(shift_reg, iv_buf, BS);
            u4byte keystream[4];

            size_t pos = 0;
            while (pos < ct_len) {
                cipher.encrypt_block(
                    reinterpret_cast<const u4byte*>(shift_reg), keystream);
                auto* ks = reinterpret_cast<unsigned char*>(keystream);
                size_t chunk = std::min((size_t)fb, ct_len - pos);
                // XOR to get plaintext
                xor_blocks(ct_data + pos, ks, pt_data + pos, chunk);
                // Shift register: shift left by chunk, append ciphertext
                if (chunk < BS) {
                    std::memmove(shift_reg, shift_reg + chunk, BS - chunk);
                    std::memcpy(shift_reg + BS - chunk, ct_data + pos, chunk);
                } else {
                    std::memcpy(shift_reg, ct_data + pos, BS);
                }
                pos += chunk;
            }
            return true;
        }

        // ── OFB (nofb) ──
        if (mode == "nofb" || mode == "ofb") {
            plaintext.resize(ct_len);
            auto* pt_data = reinterpret_cast<unsigned char*>(&plaintext[0]);
            unsigned char feedback[BS];
            std::memcpy(feedback, iv_buf, BS);
            u4byte enc_out[4];

            size_t pos = 0;
            while (pos < ct_len) {
                cipher.encrypt_block(
                    reinterpret_cast<const u4byte*>(feedback), enc_out);
                std::memcpy(feedback, enc_out, BS);
                size_t chunk = std::min((size_t)BS, ct_len - pos);
                xor_blocks(ct_data + pos,
                           reinterpret_cast<unsigned char*>(enc_out),
                           pt_data + pos, chunk);
                pos += chunk;
            }
            return true;
        }

        // ── CTR ──
        if (mode == "ctr") {
            plaintext.resize(ct_len);
            auto* pt_data = reinterpret_cast<unsigned char*>(&plaintext[0]);
            unsigned char counter[BS];
            std::memcpy(counter, iv_buf, BS);
            u4byte enc_out[4];

            size_t pos = 0;
            while (pos < ct_len) {
                cipher.encrypt_block(
                    reinterpret_cast<const u4byte*>(counter), enc_out);
                size_t chunk = std::min((size_t)BS, ct_len - pos);
                xor_blocks(ct_data + pos,
                           reinterpret_cast<unsigned char*>(enc_out),
                           pt_data + pos, chunk);
                increment_counter(counter, BS);
                pos += chunk;
            }
            return true;
        }

        // Unknown mode
        return false;

    } catch (...) {
        plaintext.clear();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void register_gladman_ciphers(std::map<std::string, DecryptFunc>& m) {
    for (size_t i = 0; i < NUM_GLADMAN; ++i) {
        const GladmanCipher* pc = &GLADMAN_CIPHERS[i];
        m[pc->name] = [pc](const std::string& mode,
                           const std::string& ct,
                           const std::string& key,
                           const std::string& iv,
                           std::string& plaintext) {
            return gladman_try_decrypt(*pc, mode, ct, key, iv, plaintext);
        };
    }
}
