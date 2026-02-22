/**
 * Botan 2.x Cipher Adapter
 *
 * Provides DecryptFunc-compatible wrappers for 3 Botan block ciphers:
 * MISTY1, KASUMI, Noekeon
 *
 * These ciphers were removed in Botan 3.0 and require Botan 2.19.3.
 * MISTY1/KASUMI are 64-bit block, Noekeon is 128-bit block.
 * Mode implementations (ECB/CBC/CFB/OFB/CTR) are done manually using
 * Botan's raw BlockCipher API.
 */

#include "botan_ciphers.h"

#include <botan/block_cipher.h>

#include <cstring>
#include <string>
#include <algorithm>
#include <memory>

// ---------------------------------------------------------------------------
// Cipher descriptor
// ---------------------------------------------------------------------------

struct BotanCipherDesc {
    const char* our_name;    // name used in CIPHER_SPECS / dispatch map
    const char* botan_name;  // name passed to Botan::BlockCipher::create()
};

static const BotanCipherDesc BOTAN_CIPHERS[] = {
    {"misty1",  "MISTY1"},
    {"kasumi",  "KASUMI"},
    {"noekeon", "Noekeon"},
};

static constexpr size_t NUM_BOTAN = sizeof(BOTAN_CIPHERS) / sizeof(BOTAN_CIPHERS[0]);
static constexpr size_t MAX_BS = 16;  // largest block size (Noekeon)

// ---------------------------------------------------------------------------
// XOR helper
// ---------------------------------------------------------------------------

static void xor_blocks(const uint8_t* a, const uint8_t* b,
                       uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++)
        out[i] = a[i] ^ b[i];
}

// ---------------------------------------------------------------------------
// Counter increment (big-endian, rightmost byte first)
// ---------------------------------------------------------------------------

static void increment_counter(uint8_t* ctr, size_t len) {
    for (size_t i = len; i > 0; --i) {
        if (++ctr[i - 1] != 0) break;
    }
}

// ---------------------------------------------------------------------------
// Parse cfb-N mode string
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

static bool botan_try_decrypt(
    const BotanCipherDesc& desc,
    const std::string& mode,
    const std::string& ct,
    const std::string& key,
    const std::string& iv,
    std::string& plaintext)
{
    try {
        size_t ct_len = ct.size();
        if (ct_len == 0) return false;

        // Create cipher instance
        auto cipher = Botan::BlockCipher::create(desc.botan_name);
        if (!cipher) return false;

        const size_t BS = cipher->block_size();

        // Set key
        cipher->set_key(reinterpret_cast<const uint8_t*>(key.data()), key.size());

        // Prepare IV
        uint8_t iv_buf[MAX_BS];
        std::memset(iv_buf, 0, MAX_BS);
        if (!iv.empty()) {
            size_t iv_copy = std::min(iv.size(), BS);
            std::memcpy(iv_buf, iv.data(), iv_copy);
        }

        const auto* ct_data = reinterpret_cast<const uint8_t*>(ct.data());

        // ── ECB ──
        if (mode == "ecb") {
            if (ct_len % BS != 0) return false;
            plaintext.resize(ct_len);
            auto* pt_data = reinterpret_cast<uint8_t*>(&plaintext[0]);
            for (size_t i = 0; i < ct_len; i += BS) {
                cipher->decrypt(ct_data + i, pt_data + i);
            }
            return true;
        }

        // ── CBC ──
        if (mode == "cbc") {
            if (ct_len % BS != 0) return false;
            plaintext.resize(ct_len);
            auto* pt_data = reinterpret_cast<uint8_t*>(&plaintext[0]);
            const uint8_t* prev = iv_buf;
            uint8_t tmp[MAX_BS];
            for (size_t i = 0; i < ct_len; i += BS) {
                cipher->decrypt(ct_data + i, tmp);
                xor_blocks(tmp, prev, pt_data + i, BS);
                prev = ct_data + i;
            }
            return true;
        }

        // ── CFB (variable feedback size) ──
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
            auto* pt_data = reinterpret_cast<uint8_t*>(&plaintext[0]);
            uint8_t shift_reg[MAX_BS];
            std::memcpy(shift_reg, iv_buf, BS);
            uint8_t keystream[MAX_BS];

            size_t pos = 0;
            while (pos < ct_len) {
                cipher->encrypt(shift_reg, keystream);
                size_t chunk = std::min((size_t)fb, ct_len - pos);
                xor_blocks(ct_data + pos, keystream, pt_data + pos, chunk);
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
            auto* pt_data = reinterpret_cast<uint8_t*>(&plaintext[0]);
            uint8_t feedback[MAX_BS];
            std::memcpy(feedback, iv_buf, BS);
            uint8_t enc_out[MAX_BS];

            size_t pos = 0;
            while (pos < ct_len) {
                cipher->encrypt(feedback, enc_out);
                std::memcpy(feedback, enc_out, BS);
                size_t chunk = std::min(BS, ct_len - pos);
                xor_blocks(ct_data + pos, enc_out, pt_data + pos, chunk);
                pos += chunk;
            }
            return true;
        }

        // ── CTR ──
        if (mode == "ctr") {
            plaintext.resize(ct_len);
            auto* pt_data = reinterpret_cast<uint8_t*>(&plaintext[0]);
            uint8_t counter[MAX_BS];
            std::memcpy(counter, iv_buf, BS);
            uint8_t enc_out[MAX_BS];

            size_t pos = 0;
            while (pos < ct_len) {
                cipher->encrypt(counter, enc_out);
                size_t chunk = std::min(BS, ct_len - pos);
                xor_blocks(ct_data + pos, enc_out, pt_data + pos, chunk);
                increment_counter(counter, BS);
                pos += chunk;
            }
            return true;
        }

        return false;

    } catch (...) {
        plaintext.clear();
        return false;
    }
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

void register_botan_ciphers(std::map<std::string, DecryptFunc>& m) {
    for (size_t i = 0; i < NUM_BOTAN; ++i) {
        const BotanCipherDesc* pd = &BOTAN_CIPHERS[i];
        m[pd->our_name] = [pd](const std::string& mode,
                               const std::string& ct,
                               const std::string& key,
                               const std::string& iv,
                               std::string& plaintext) {
            return botan_try_decrypt(*pd, mode, ct, key, iv, plaintext);
        };
    }
}
