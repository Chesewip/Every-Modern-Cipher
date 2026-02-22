/**
 * Standalone Block Cipher Adapter
 *
 * Provides DecryptFunc-compatible wrappers for 4 standalone block ciphers:
 * CLEFIA (128-bit block), Anubis (128-bit block), Khazad (64-bit block),
 * Kuznyechik (128-bit block)
 *
 * Mode implementations (ECB/CBC/CFB/OFB/CTR) are done manually using
 * a uniform byte-level API abstraction over each cipher's native interface.
 */

#include "standalone_ciphers.h"

#include <cstring>
#include <string>
#include <algorithm>
#include <cstdint>
#include <vector>

// ---------------------------------------------------------------------------
// Forward declarations of cipher functions from wrapper translation units
// ---------------------------------------------------------------------------

namespace standalone_clefia {
    int ClefiaKeySet(unsigned char *rk, const unsigned char *skey, const int key_bitlen);
    void ClefiaEncrypt(unsigned char *ct, const unsigned char *pt, const unsigned char *rk, const int r);
    void ClefiaDecrypt(unsigned char *pt, const unsigned char *ct, const unsigned char *rk, const int r);
}

namespace standalone_anubis {
    struct anubis_ctx {
        int key_len;
        int R;
        uint32_t E[19][4];
        uint32_t D[19][4];
    };
    int anubis_setkey(struct anubis_ctx *ctx, const uint8_t *in_key, unsigned int key_len);
    void anubis_encrypt(struct anubis_ctx *ctx, uint8_t *dst, const uint8_t *src);
    void anubis_decrypt(struct anubis_ctx *ctx, uint8_t *dst, const uint8_t *src);
}

namespace standalone_khazad {
    struct khazad_ctx {
        uint64_t E[9];
        uint64_t D[9];
    };
    int khazad_setkey(struct khazad_ctx *ctx, const uint8_t *in_key, unsigned int key_len);
    void khazad_encrypt(struct khazad_ctx *ctx, uint8_t *dst, const uint8_t *src);
    void khazad_decrypt(struct khazad_ctx *ctx, uint8_t *dst, const uint8_t *src);
}

namespace standalone_kuznyechik {
    struct kuznyechik_subkeys {
        uint64_t ek[20];
        uint64_t dk[20];
    };
    int kuznyechik_set_key(struct kuznyechik_subkeys *subkeys, const unsigned char *key);
    void kuznyechik_encrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out, const unsigned char *in);
    void kuznyechik_decrypt(struct kuznyechik_subkeys *subkeys, unsigned char *out, const unsigned char *in);
}

// ---------------------------------------------------------------------------
// Cipher descriptor with function-pointer abstraction
// ---------------------------------------------------------------------------

struct StandaloneCipher {
    using SetKeyFn      = bool(*)(void* ctx, const uint8_t* key, size_t key_len);
    using BlockFn       = void(*)(void* ctx, const uint8_t* in, uint8_t* out);
    using CtxSizeFn     = size_t(*)();

    const char* name;
    size_t      block_size;
    SetKeyFn    set_key;
    BlockFn     encrypt_block;
    BlockFn     decrypt_block;
    CtxSizeFn   ctx_size;
};

// ---------------------------------------------------------------------------
// CLEFIA adapter functions
// ---------------------------------------------------------------------------

// CLEFIA context: round keys + round count
struct ClefiaCtx {
    unsigned char rk[8 * 26 + 16]; // max round keys
    int r;                          // number of rounds
};

static bool clefia_set_key(void* ctx, const uint8_t* key, size_t key_len) {
    auto* c = static_cast<ClefiaCtx*>(ctx);
    int bitlen = (int)(key_len * 8);
    c->r = standalone_clefia::ClefiaKeySet(c->rk, key, bitlen);
    return c->r != 0;
}

static void clefia_encrypt(void* ctx, const uint8_t* in, uint8_t* out) {
    auto* c = static_cast<ClefiaCtx*>(ctx);
    standalone_clefia::ClefiaEncrypt(out, in, c->rk, c->r);
}

static void clefia_decrypt(void* ctx, const uint8_t* in, uint8_t* out) {
    auto* c = static_cast<ClefiaCtx*>(ctx);
    standalone_clefia::ClefiaDecrypt(out, in, c->rk, c->r);
}

static size_t clefia_ctx_size() { return sizeof(ClefiaCtx); }

// ---------------------------------------------------------------------------
// Anubis adapter functions
// ---------------------------------------------------------------------------

static bool anubis_set_key(void* ctx, const uint8_t* key, size_t key_len) {
    auto* c = static_cast<standalone_anubis::anubis_ctx*>(ctx);
    return standalone_anubis::anubis_setkey(c, key, (unsigned int)key_len) == 0;
}

static void anubis_encrypt(void* ctx, const uint8_t* in, uint8_t* out) {
    auto* c = static_cast<standalone_anubis::anubis_ctx*>(ctx);
    standalone_anubis::anubis_encrypt(c, out, in);
}

static void anubis_decrypt(void* ctx, const uint8_t* in, uint8_t* out) {
    auto* c = static_cast<standalone_anubis::anubis_ctx*>(ctx);
    standalone_anubis::anubis_decrypt(c, out, in);
}

static size_t anubis_ctx_size() { return sizeof(standalone_anubis::anubis_ctx); }

// ---------------------------------------------------------------------------
// Khazad adapter functions
// ---------------------------------------------------------------------------

static bool khazad_set_key(void* ctx, const uint8_t* key, size_t key_len) {
    auto* c = static_cast<standalone_khazad::khazad_ctx*>(ctx);
    return standalone_khazad::khazad_setkey(c, key, (unsigned int)key_len) == 0;
}

static void khazad_encrypt(void* ctx, const uint8_t* in, uint8_t* out) {
    auto* c = static_cast<standalone_khazad::khazad_ctx*>(ctx);
    standalone_khazad::khazad_encrypt(c, out, in);
}

static void khazad_decrypt(void* ctx, const uint8_t* in, uint8_t* out) {
    auto* c = static_cast<standalone_khazad::khazad_ctx*>(ctx);
    standalone_khazad::khazad_decrypt(c, out, in);
}

static size_t khazad_ctx_size() { return sizeof(standalone_khazad::khazad_ctx); }

// ---------------------------------------------------------------------------
// Kuznyechik adapter functions
// ---------------------------------------------------------------------------

static bool kuznyechik_set_key(void* ctx, const uint8_t* key, size_t key_len) {
    (void)key_len; // always 32 bytes
    auto* c = static_cast<standalone_kuznyechik::kuznyechik_subkeys*>(ctx);
    return standalone_kuznyechik::kuznyechik_set_key(c, key) == 0;
}

static void kuznyechik_encrypt(void* ctx, const uint8_t* in, uint8_t* out) {
    auto* c = static_cast<standalone_kuznyechik::kuznyechik_subkeys*>(ctx);
    standalone_kuznyechik::kuznyechik_encrypt(c, out, in);
}

static void kuznyechik_decrypt(void* ctx, const uint8_t* in, uint8_t* out) {
    auto* c = static_cast<standalone_kuznyechik::kuznyechik_subkeys*>(ctx);
    standalone_kuznyechik::kuznyechik_decrypt(c, out, in);
}

static size_t kuznyechik_ctx_size() { return sizeof(standalone_kuznyechik::kuznyechik_subkeys); }

// ---------------------------------------------------------------------------
// Cipher table
// ---------------------------------------------------------------------------

static const StandaloneCipher STANDALONE_CIPHERS[] = {
    {"clefia",      16, clefia_set_key,      clefia_encrypt,      clefia_decrypt,      clefia_ctx_size},
    {"anubis",      16, anubis_set_key,      anubis_encrypt,      anubis_decrypt,      anubis_ctx_size},
    {"khazad",       8, khazad_set_key,      khazad_encrypt,      khazad_decrypt,      khazad_ctx_size},
    {"kuznyechik",  16, kuznyechik_set_key,  kuznyechik_encrypt,  kuznyechik_decrypt,  kuznyechik_ctx_size},
};

static constexpr size_t NUM_STANDALONE = sizeof(STANDALONE_CIPHERS) / sizeof(STANDALONE_CIPHERS[0]);
static constexpr size_t MAX_BS = 16;  // largest block size
static constexpr size_t MAX_CTX = 2048; // largest context (generous upper bound)

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

static bool standalone_try_decrypt(
    const StandaloneCipher& cipher,
    const std::string& mode,
    const std::string& ct,
    const std::string& key,
    const std::string& iv,
    std::string& plaintext)
{
    try {
        size_t ct_len = ct.size();
        if (ct_len == 0) return false;

        const size_t BS = cipher.block_size;

        // Allocate context on heap for safety (some contexts are large)
        std::vector<uint8_t> ctx_buf(cipher.ctx_size(), 0);
        void* ctx = ctx_buf.data();

        // Set key
        if (!cipher.set_key(ctx, reinterpret_cast<const uint8_t*>(key.data()), key.size()))
            return false;

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
                cipher.decrypt_block(ctx, ct_data + i, pt_data + i);
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
                cipher.decrypt_block(ctx, ct_data + i, tmp);
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
                cipher.encrypt_block(ctx, shift_reg, keystream);
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
                cipher.encrypt_block(ctx, feedback, enc_out);
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
                cipher.encrypt_block(ctx, counter, enc_out);
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

void register_standalone_ciphers(std::map<std::string, DecryptFunc>& m) {
    for (size_t i = 0; i < NUM_STANDALONE; ++i) {
        const StandaloneCipher* pc = &STANDALONE_CIPHERS[i];
        m[pc->name] = [pc](const std::string& mode,
                           const std::string& ct,
                           const std::string& key,
                           const std::string& iv,
                           std::string& plaintext) {
            return standalone_try_decrypt(*pc, mode, ct, key, iv, plaintext);
        };
    }
}
