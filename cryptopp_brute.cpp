/**
 * Crypto++ Brute-Force Cipher Testing Tool
 *
 * Tests ciphertext against Crypto++ cipher algorithms using a wordlist and
 * optional IV list. Scores results by printable ASCII %.
 * Supports 30 block ciphers and 6 stream ciphers.
 *
 * Usage: cryptopp_brute --ct <file> --wl <file> [options]
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <functional>
#include <cmath>
#include <cstdint>
#include <chrono>
#include <stdexcept>
#include <iomanip>
#include <cstring>

// Crypto++ headers — block ciphers
#include <cryptopp/idea.h>
#include <cryptopp/rc5.h>
#include <cryptopp/rc6.h>
#include <cryptopp/mars.h>
#include <cryptopp/skipjack.h>
#include <cryptopp/3way.h>
#include <cryptopp/safer.h>
#include <cryptopp/aria.h>
#include <cryptopp/sm4.h>
#include <cryptopp/lea.h>
#include <cryptopp/hight.h>
#include <cryptopp/tea.h>
#include <cryptopp/square.h>
#include <cryptopp/shark.h>
#include <cryptopp/shacal2.h>
#include <cryptopp/simon.h>
#include <cryptopp/speck.h>
#include <cryptopp/simeck.h>
#include <cryptopp/cham.h>
#include <cryptopp/kalyna.h>
#include <cryptopp/threefish.h>

// Crypto++ headers — stream ciphers
#include <cryptopp/salsa.h>
#include <cryptopp/sosemanuk.h>
#include <cryptopp/rabbit.h>
#include <cryptopp/hc128.h>
#include <cryptopp/hc256.h>
#include <cryptopp/panama.h>
#include <cryptopp/seal.h>

// Crypto++ headers — modes & infrastructure
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/secblock.h>

// Gladman AES Round 1 ciphers
#include "gladman_ciphers.h"

// Botan 2.x ciphers (MISTY1, KASUMI, Noekeon)
#include "botan_ciphers.h"

// Standalone block ciphers (CLEFIA, Anubis, Khazad, Kuznyechik)
#include "standalone_ciphers.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void info(const std::string& msg) {
    std::cout << "[INFO] " << msg << std::endl;
    std::cout.flush();
}

static void emit_progress(double fraction) {
    char buf[64];
    snprintf(buf, sizeof(buf), "[PROGRESS] %.5f", fraction);
    std::cerr << buf << std::endl;
    std::cerr.flush();
}

static double score_printable(const std::string& data) {
    if (data.empty()) return 0.0;
    size_t printable = 0;
    for (unsigned char b : data) {
        if ((b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0A || b == 0x0D)
            printable++;
    }
    return static_cast<double>(printable) / data.size();
}

static std::string safe_preview(const std::string& data, size_t max_len = 80) {
    std::string out;
    size_t len = std::min(data.size(), max_len);
    for (size_t i = 0; i < len; i++) {
        unsigned char b = static_cast<unsigned char>(data[i]);
        if ((b >= 0x20 && b <= 0x7E) || b == 0x09)
            out += static_cast<char>(b);
        else
            out += '.';
    }
    return out;
}

static std::string bytes_to_hex(const std::string& data) {
    std::string out;
    out.reserve(data.size() * 2);
    static const char hex_chars[] = "0123456789abcdef";
    for (unsigned char b : data) {
        out += hex_chars[b >> 4];
        out += hex_chars[b & 0x0F];
    }
    return out;
}

static std::string hex_to_bytes(const std::string& hex) {
    std::string trimmed;
    for (char c : hex) {
        if (c != ' ' && c != '\t' && c != '\n' && c != '\r')
            trimmed += c;
    }
    if (trimmed.size() % 2 != 0)
        trimmed = "0" + trimmed;
    std::string out;
    out.reserve(trimmed.size() / 2);
    for (size_t i = 0; i + 1 < trimmed.size(); i += 2) {
        char hi = trimmed[i], lo = trimmed[i + 1];
        auto hexval = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return -1;
        };
        int h = hexval(hi), l = hexval(lo);
        if (h < 0 || l < 0) return "";
        out += static_cast<char>((h << 4) | l);
    }
    return out;
}

static bool is_valid_hex(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return s.size() % 2 == 0;
}

static std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}

static std::string to_lower(const std::string& s) {
    std::string out = s;
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c += 32;
    return out;
}

// ---------------------------------------------------------------------------
// Encoding detection & ciphertext decoding
// ---------------------------------------------------------------------------

static std::string detect_encoding(const std::string& data) {
    if (is_valid_hex(data)) return "hex";

    // Base64 check
    static const std::string b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
    bool all_b64 = true;
    for (char c : data) {
        if (b64chars.find(c) == std::string::npos) {
            all_b64 = false;
            break;
        }
    }
    if (all_b64 && !data.empty()) return "base64";
    return "hex";
}

static std::string base64_decode(const std::string& encoded) {
    static const int b64_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        int v = b64_table[c];
        if (v == -2) break; // '='
        if (v < 0) continue;
        val = (val << 6) | v;
        valb += 6;
        if (valb >= 0) {
            out += static_cast<char>((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

static std::string decode_ct(const std::string& raw, const std::string& encoding) {
    if (encoding == "hex") {
        return hex_to_bytes(raw);
    } else {
        return base64_decode(raw);
    }
}

// ---------------------------------------------------------------------------
// Caesar rotation & reverse on encoded strings
// ---------------------------------------------------------------------------

static std::string caesar_rotate_hex(const std::string& s, int shift) {
    static const char hex_alpha[] = "0123456789abcdef";
    std::string lower = to_lower(s);
    std::string out;
    out.reserve(lower.size());
    for (char c : lower) {
        const char* p = std::strchr(hex_alpha, c);
        if (p) {
            int pos = static_cast<int>(p - hex_alpha);
            out += hex_alpha[(pos + shift) % 16];
        } else {
            out += c;
        }
    }
    return out;
}

static std::string caesar_rotate_base64(const std::string& s, int shift) {
    static const char b64_alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        const char* p = std::strchr(b64_alpha, c);
        if (p) {
            int pos = static_cast<int>(p - b64_alpha);
            out += b64_alpha[(pos + shift) % 64];
        } else {
            out += c; // keep '=' as-is
        }
    }
    return out;
}

static std::string try_decode_variant(const std::string& encoded, const std::string& encoding) {
    if (encoding == "hex") {
        std::string lower = to_lower(encoded);
        if (!is_valid_hex(lower)) return "";
        return hex_to_bytes(lower);
    } else {
        return base64_decode(encoded);
    }
}

struct CTVariant {
    std::string label;
    std::string data;
};

static std::vector<CTVariant> generate_ct_variants(
    const std::string& ct_raw, const std::string& encoding,
    bool do_reverse, bool do_caesar, bool do_char_shift)
{
    std::string trimmed = trim(ct_raw);

    // Phase 1: Build (label, encoded_string) pairs
    struct EncVar { std::string label; std::string enc; };
    std::vector<EncVar> enc_variants;
    enc_variants.push_back({"original", trimmed});

    if (do_reverse) {
        std::string rev(trimmed.rbegin(), trimmed.rend());
        enc_variants.push_back({"reversed", rev});
    }

    if (do_caesar) {
        int max_shift = (encoding == "hex") ? 15 : 63;
        for (int shift = 1; shift <= max_shift; shift++) {
            std::string rotated;
            if (encoding == "hex")
                rotated = caesar_rotate_hex(trimmed, shift);
            else
                rotated = caesar_rotate_base64(trimmed, shift);
            enc_variants.push_back({"caesar-" + std::to_string(shift), rotated});

            if (do_reverse) {
                std::string rev_rot(rotated.rbegin(), rotated.rend());
                enc_variants.push_back({"rev+caesar-" + std::to_string(shift), rev_rot});
            }
        }
    }

    // Phase 2: Character-level cyclic shifts on encoded strings
    if (do_char_shift) {
        size_t base_count = enc_variants.size();
        for (size_t vi = 0; vi < base_count; vi++) {
            size_t len = enc_variants[vi].enc.size();
            for (size_t s = 1; s < len; s++) {
                enc_variants.push_back({
                    enc_variants[vi].label + "+shift-" + std::to_string(s),
                    enc_variants[vi].enc.substr(s) + enc_variants[vi].enc.substr(0, s)
                });
            }
        }
    }

    // Phase 3: Decode all variants
    std::vector<CTVariant> variants;
    for (const auto& ev : enc_variants) {
        auto decoded = try_decode_variant(ev.enc, encoding);
        if (!decoded.empty())
            variants.push_back({ev.label, decoded});
    }

    return variants;
}

// ---------------------------------------------------------------------------
// Cipher spec definitions
// ---------------------------------------------------------------------------

struct CipherSpec {
    std::string name;
    size_t block_size;                   // 0 for stream ciphers
    std::vector<size_t> valid_key_sizes; // empty = variable
    size_t min_key;
    size_t max_key;
    bool is_stream;
    size_t iv_size;                      // for stream ciphers (nonce/IV)
};

static const std::vector<CipherSpec> CIPHER_SPECS = {
    // ── Original 8 block ciphers ──
    {"idea",           8,   {16},           16,  16,  false, 0},
    {"rc5",            8,   {},             1,   255, false, 0},
    {"rc6",            16,  {16, 24, 32},   16,  32,  false, 0},
    {"mars",           16,  {},             16,  56,  false, 0},
    {"skipjack",       8,   {10},           10,  10,  false, 0},
    {"3way",           12,  {12},           12,  12,  false, 0},
    {"safer-sk64",     8,   {8},            8,   8,   false, 0},
    {"safer-sk128",    8,   {16},           16,  16,  false, 0},

    // ── New block ciphers ──
    {"aria",           16,  {16, 24, 32},   16,  32,  false, 0},
    {"sm4",            16,  {16},           16,  16,  false, 0},
    {"lea",            16,  {16, 24, 32},   16,  32,  false, 0},
    {"hight",          8,   {16},           16,  16,  false, 0},
    {"tea",            8,   {16},           16,  16,  false, 0},
    {"square",         16,  {16},           16,  16,  false, 0},
    {"shark",          8,   {16},           16,  16,  false, 0},
    {"shacal2",        32,  {},             16,  64,  false, 0},
    {"simon-64",       8,   {12, 16},       12,  16,  false, 0},
    {"simon-128",      16,  {16, 24, 32},   16,  32,  false, 0},
    {"speck-64",       8,   {12, 16},       12,  16,  false, 0},
    {"speck-128",      16,  {16, 24, 32},   16,  32,  false, 0},
    {"simeck-32",      4,   {8},            8,   8,   false, 0},
    {"simeck-64",      8,   {16},           16,  16,  false, 0},
    {"cham-64",        8,   {16},           16,  16,  false, 0},
    {"cham-128",       16,  {16, 32},       16,  32,  false, 0},
    {"kalyna-128",     16,  {16, 32},       16,  32,  false, 0},
    {"kalyna-256",     32,  {32, 64},       32,  64,  false, 0},
    {"kalyna-512",     64,  {64},           64,  64,  false, 0},
    {"threefish-256",  32,  {32},           32,  32,  false, 0},
    {"threefish-512",  64,  {64},           64,  64,  false, 0},
    {"threefish-1024", 128, {128},          128, 128, false, 0},

    // ── Gladman AES Round 1 candidates (128-bit block) ──
    {"crypton",        16,  {16, 24, 32},   16,  32,  false, 0},
    {"dfc",            16,  {16, 24, 32},   16,  32,  false, 0},
    {"e2",             16,  {16, 24, 32},   16,  32,  false, 0},
    {"frog",           16,  {},              5, 125,  false, 0},
    {"magenta",        16,  {16, 24, 32},   16,  32,  false, 0},
    {"hpc",            16,  {16, 24, 32},   16,  32,  false, 0},

    // ── Botan block ciphers ──
    {"misty1",         8,   {16},           16,  16,  false, 0},
    {"kasumi",         8,   {16},           16,  16,  false, 0},
    {"noekeon",        16,  {16},           16,  16,  false, 0},

    // ── Standalone block ciphers ──
    {"clefia",         16,  {16, 24, 32},   16,  32,  false, 0},
    {"anubis",         16,  {},             16,  40,  false, 0},
    {"khazad",          8,  {16},           16,  16,  false, 0},
    {"kuznyechik",     16,  {32},           32,  32,  false, 0},

    // ── Stream ciphers ──
    {"sosemanuk",      0,   {},             1,   32,  true,  16},
    {"rabbit",         0,   {16},           16,  16,  true,  8},
    {"hc-128",         0,   {16},           16,  16,  true,  16},
    {"hc-256",         0,   {32},           32,  32,  true,  32},
    {"panama",         0,   {32},           32,  32,  true,  32},
    {"seal",           0,   {20},           20,  20,  true,  4},
    {"xsalsa20",       0,   {32},           32,  32,  true,  24},
};

static const CipherSpec* find_cipher_spec(const std::string& name) {
    for (auto& cs : CIPHER_SPECS) {
        if (cs.name == name) return &cs;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Key / IV fitting
// ---------------------------------------------------------------------------

static std::string fit_key(const std::string& key, const CipherSpec& spec) {
    if (!spec.valid_key_sizes.empty()) {
        size_t kl = key.size();
        // Find smallest valid size >= key length, or largest
        auto sizes = spec.valid_key_sizes;
        std::sort(sizes.begin(), sizes.end());
        size_t target = sizes.back();
        for (size_t s : sizes) {
            if (kl <= s) { target = s; break; }
        }
        if (kl < target) {
            std::string padded = key;
            padded.resize(target, '\0');
            return padded;
        } else if (kl > target) {
            return key.substr(0, target);
        }
        return key;
    } else {
        // Variable key size
        size_t kl = key.size();
        if (kl < spec.min_key) {
            std::string padded = key;
            padded.resize(spec.min_key, '\0');
            return padded;
        } else if (kl > spec.max_key) {
            return key.substr(0, spec.max_key);
        }
        return key;
    }
}

static std::string fit_iv(const std::string& iv, size_t required) {
    if (required == 0) return "";
    size_t ivl = iv.size();
    if (ivl < required) {
        std::string padded = iv;
        padded.resize(required, '\0');
        return padded;
    } else if (ivl > required) {
        return iv.substr(0, required);
    }
    return iv;
}

// ---------------------------------------------------------------------------
// Decryption via Crypto++ templates
// ---------------------------------------------------------------------------

using DecryptFunc = std::function<bool(
    const std::string& mode,
    const std::string& ct,
    const std::string& key,
    const std::string& iv,
    std::string& plaintext
)>;

template<typename CipherT>
bool try_decrypt_all_modes(
    const std::string& mode,
    const std::string& ct,
    const std::string& key,
    const std::string& iv,
    std::string& plaintext)
{
    try {
        CryptoPP::byte* key_ptr = (CryptoPP::byte*)key.data();
        size_t key_len = key.size();
        CryptoPP::byte* iv_ptr = (CryptoPP::byte*)iv.data();
        CryptoPP::byte* ct_ptr = (CryptoPP::byte*)ct.data();
        size_t ct_len = ct.size();

        if (mode == "ecb") {
            typename CryptoPP::ECB_Mode<CipherT>::Decryption dec;
            dec.SetKey(key_ptr, key_len);
            CryptoPP::StringSource ss(
                ct_ptr, ct_len, true,
                new CryptoPP::StreamTransformationFilter(
                    dec, new CryptoPP::StringSink(plaintext),
                    CryptoPP::StreamTransformationFilter::NO_PADDING
                )
            );
        } else if (mode == "cbc") {
            typename CryptoPP::CBC_Mode<CipherT>::Decryption dec;
            dec.SetKeyWithIV(key_ptr, key_len, iv_ptr);
            CryptoPP::StringSource ss(
                ct_ptr, ct_len, true,
                new CryptoPP::StreamTransformationFilter(
                    dec, new CryptoPP::StringSink(plaintext),
                    CryptoPP::StreamTransformationFilter::NO_PADDING
                )
            );
        } else if (mode == "cfb" || parse_cfb_feedback(mode) > 0) {
            // CFB with configurable feedback size
            // cfb = 1 byte (8-bit, matches mcrypt's cfb)
            // cfb-N = N/8 bytes
            int fb = (mode == "cfb") ? 1 : parse_cfb_feedback(mode);
            typename CryptoPP::CFB_Mode<CipherT>::Decryption dec;
            CryptoPP::AlgorithmParameters params =
                CryptoPP::MakeParameters(CryptoPP::Name::FeedbackSize(), fb);
            dec.SetKey(key_ptr, key_len, params);
            dec.Resynchronize(iv_ptr);
            CryptoPP::StringSource ss(
                ct_ptr, ct_len, true,
                new CryptoPP::StreamTransformationFilter(
                    dec, new CryptoPP::StringSink(plaintext)
                )
            );
        } else if (mode == "ncfb") {
            // Full-block CFB (matches mcrypt's ncfb — feedback = block size)
            typename CryptoPP::CFB_Mode<CipherT>::Decryption dec;
            dec.SetKeyWithIV(key_ptr, key_len, iv_ptr);
            CryptoPP::StringSource ss(
                ct_ptr, ct_len, true,
                new CryptoPP::StreamTransformationFilter(
                    dec, new CryptoPP::StringSink(plaintext)
                )
            );
        } else if (mode == "nofb" || mode == "ofb") {
            typename CryptoPP::OFB_Mode<CipherT>::Decryption dec;
            dec.SetKeyWithIV(key_ptr, key_len, iv_ptr);
            CryptoPP::StringSource ss(
                ct_ptr, ct_len, true,
                new CryptoPP::StreamTransformationFilter(
                    dec, new CryptoPP::StringSink(plaintext)
                )
            );
        } else if (mode == "ctr") {
            typename CryptoPP::CTR_Mode<CipherT>::Decryption dec;
            dec.SetKeyWithIV(key_ptr, key_len, iv_ptr);
            CryptoPP::StringSource ss(
                ct_ptr, ct_len, true,
                new CryptoPP::StreamTransformationFilter(
                    dec, new CryptoPP::StringSink(plaintext)
                )
            );
        } else {
            return false;
        }
        return true;
    } catch (const CryptoPP::Exception&) {
        plaintext.clear();
        return false;
    } catch (const std::exception&) {
        plaintext.clear();
        return false;
    }
}

// Stream cipher decryption template (mode must be "stream")
template<typename DecryptionT>
bool try_decrypt_stream(
    const std::string& mode,
    const std::string& ct,
    const std::string& key,
    const std::string& iv,
    std::string& plaintext)
{
    if (mode != "stream") return false;
    try {
        DecryptionT dec;
        if (iv.empty())
            dec.SetKey((CryptoPP::byte*)key.data(), key.size());
        else
            dec.SetKeyWithIV(
                (CryptoPP::byte*)key.data(), key.size(),
                (CryptoPP::byte*)iv.data(), iv.size());
        CryptoPP::StringSource ss(
            (CryptoPP::byte*)ct.data(), ct.size(), true,
            new CryptoPP::StreamTransformationFilter(
                dec, new CryptoPP::StringSink(plaintext)
            )
        );
        return true;
    } catch (const CryptoPP::Exception&) {
        plaintext.clear();
        return false;
    } catch (const std::exception&) {
        plaintext.clear();
        return false;
    }
}

// Build dispatch map
static std::map<std::string, DecryptFunc> build_dispatch_map() {
    std::map<std::string, DecryptFunc> m;

    // ── Original block ciphers ──
    m["idea"]        = try_decrypt_all_modes<CryptoPP::IDEA>;
    m["rc5"]         = try_decrypt_all_modes<CryptoPP::RC5>;
    m["rc6"]         = try_decrypt_all_modes<CryptoPP::RC6>;
    m["mars"]        = try_decrypt_all_modes<CryptoPP::MARS>;
    m["skipjack"]    = try_decrypt_all_modes<CryptoPP::SKIPJACK>;
    m["3way"]        = try_decrypt_all_modes<CryptoPP::ThreeWay>;
    m["safer-sk64"]  = try_decrypt_all_modes<CryptoPP::SAFER_SK>;
    m["safer-sk128"] = try_decrypt_all_modes<CryptoPP::SAFER_SK>;

    // ── New block ciphers ──
    m["aria"]           = try_decrypt_all_modes<CryptoPP::ARIA>;
    m["sm4"]            = try_decrypt_all_modes<CryptoPP::SM4>;
    m["lea"]            = try_decrypt_all_modes<CryptoPP::LEA>;
    m["hight"]          = try_decrypt_all_modes<CryptoPP::HIGHT>;
    m["tea"]            = try_decrypt_all_modes<CryptoPP::TEA>;
    m["square"]         = try_decrypt_all_modes<CryptoPP::Square>;
    m["shark"]          = try_decrypt_all_modes<CryptoPP::SHARK>;
    m["shacal2"]        = try_decrypt_all_modes<CryptoPP::SHACAL2>;
    m["simon-64"]       = try_decrypt_all_modes<CryptoPP::SIMON64>;
    m["simon-128"]      = try_decrypt_all_modes<CryptoPP::SIMON128>;
    m["speck-64"]       = try_decrypt_all_modes<CryptoPP::SPECK64>;
    m["speck-128"]      = try_decrypt_all_modes<CryptoPP::SPECK128>;
    m["simeck-32"]      = try_decrypt_all_modes<CryptoPP::SIMECK32>;
    m["simeck-64"]      = try_decrypt_all_modes<CryptoPP::SIMECK64>;
    m["cham-64"]        = try_decrypt_all_modes<CryptoPP::CHAM64>;
    m["cham-128"]       = try_decrypt_all_modes<CryptoPP::CHAM128>;
    m["kalyna-128"]     = try_decrypt_all_modes<CryptoPP::Kalyna128>;
    m["kalyna-256"]     = try_decrypt_all_modes<CryptoPP::Kalyna256>;
    m["kalyna-512"]     = try_decrypt_all_modes<CryptoPP::Kalyna512>;
    m["threefish-256"]  = try_decrypt_all_modes<CryptoPP::Threefish256>;
    m["threefish-512"]  = try_decrypt_all_modes<CryptoPP::Threefish512>;
    m["threefish-1024"] = try_decrypt_all_modes<CryptoPP::Threefish1024>;

    // ── Stream ciphers ──
    m["sosemanuk"] = try_decrypt_stream<CryptoPP::Sosemanuk::Decryption>;
    m["rabbit"]    = try_decrypt_stream<CryptoPP::RabbitWithIV::Decryption>;
    m["hc-128"]    = try_decrypt_stream<CryptoPP::HC128::Decryption>;
    m["hc-256"]    = try_decrypt_stream<CryptoPP::HC256::Decryption>;
    m["panama"]    = try_decrypt_stream<CryptoPP::PanamaCipher<CryptoPP::LittleEndian>::Decryption>;
    m["seal"]      = try_decrypt_stream<CryptoPP::SEAL<CryptoPP::BigEndian>::Decryption>;
    m["xsalsa20"]  = try_decrypt_stream<CryptoPP::XSalsa20::Decryption>;

    // ── Gladman AES Round 1 ciphers ──
    register_gladman_ciphers(m);

    // ── Botan ciphers ──
    register_botan_ciphers(m);

    // ── Standalone block ciphers ──
    register_standalone_ciphers(m);

    return m;
}

// Base modes (always listed)
static const std::vector<std::string> BASE_MODES = {
    "ecb", "cbc", "cfb", "ncfb", "nofb", "ofb", "ctr", "stream"
};

// CFB feedback-size variants: cfb-8 (=cfb) through cfb-128 in 8-bit steps
static const std::vector<std::string> CFB_MODES = {
    "cfb-8", "cfb-16", "cfb-24", "cfb-32", "cfb-40", "cfb-48",
    "cfb-56", "cfb-64", "cfb-72", "cfb-80", "cfb-88", "cfb-96",
    "cfb-104", "cfb-112", "cfb-120", "cfb-128"
};

// Combined list for --list-modes and "all"
static std::vector<std::string> build_all_modes() {
    std::vector<std::string> all = BASE_MODES;
    all.insert(all.end(), CFB_MODES.begin(), CFB_MODES.end());
    return all;
}
static const std::vector<std::string> ALL_MODES = build_all_modes();

// Parse cfb-N mode string. Returns feedback size in bytes, or 0 if not a cfb-N mode.
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
// JSON escaping (hand-built — no external library)
// ---------------------------------------------------------------------------

static std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Result struct
// ---------------------------------------------------------------------------

struct HitResult {
    double score;
    std::string cipher;
    std::string mode;
    std::string variant;
    std::string key_ascii;
    std::string key_hex;
    std::string iv_hex;
    std::string preview;
};

static bool cmp_score_desc(const HitResult& a, const HitResult& b) {
    return a.score > b.score;
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct Options {
    std::string ct_path;
    std::string wl_path;
    std::string ivs_path;
    std::string encoding = "auto";
    std::string ciphers_arg = "all";
    std::string modes_arg = "all";
    double threshold = 0.70;
    int top = 50;
    std::string key_format = "raw";
    std::string iv_format = "hex";
    bool list_ciphers = false;
    bool list_modes = false;
    bool do_reverse = false;
    bool do_caesar = false;
    bool do_char_shift = false;
    bool reverse_key = false;
};

static Options parse_args(int argc, char* argv[]) {
    Options opts;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--ct" && i + 1 < argc) {
            opts.ct_path = argv[++i];
        } else if (arg == "--wl" && i + 1 < argc) {
            opts.wl_path = argv[++i];
        } else if (arg == "--ivs" && i + 1 < argc) {
            opts.ivs_path = argv[++i];
        } else if (arg == "--encoding" && i + 1 < argc) {
            opts.encoding = argv[++i];
        } else if (arg == "--ciphers" && i + 1 < argc) {
            opts.ciphers_arg = argv[++i];
        } else if (arg == "--modes" && i + 1 < argc) {
            opts.modes_arg = argv[++i];
        } else if (arg == "--threshold" && i + 1 < argc) {
            opts.threshold = std::stod(argv[++i]);
        } else if (arg == "--top" && i + 1 < argc) {
            opts.top = std::stoi(argv[++i]);
        } else if (arg == "--key-format" && i + 1 < argc) {
            opts.key_format = argv[++i];
        } else if (arg == "--iv-format" && i + 1 < argc) {
            opts.iv_format = argv[++i];
        } else if (arg == "--list-ciphers") {
            opts.list_ciphers = true;
        } else if (arg == "--list-modes") {
            opts.list_modes = true;
        } else if (arg == "--reverse") {
            opts.do_reverse = true;
        } else if (arg == "--caesar") {
            opts.do_caesar = true;
        } else if (arg == "--char-shift") {
            opts.do_char_shift = true;
        } else if (arg == "--reverse-key") {
            opts.reverse_key = true;
        } else {
            std::cerr << "[ERROR] Unknown argument: " << arg << std::endl;
            std::exit(1);
        }
    }
    return opts;
}

// ---------------------------------------------------------------------------
// Comma-split helper
// ---------------------------------------------------------------------------

static std::vector<std::string> split_comma(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream stream(s);
    std::string token;
    while (std::getline(stream, token, ',')) {
        std::string t = trim(token);
        if (!t.empty()) out.push_back(t);
    }
    return out;
}

// ---------------------------------------------------------------------------
// --list-ciphers / --list-modes
// ---------------------------------------------------------------------------

static void list_ciphers_cmd() {
    std::cout << "Supported ciphers (Crypto++):\n\n";
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "%-18s%-12s%-8s%-25s%s\n",
             "Name", "Engine", "Type", "Key sizes", "Block/IV size");
    std::cout << hdr;
    std::cout << std::string(85, '-') << "\n";

    for (auto& cs : CIPHER_SPECS) {
        std::string key_info;
        if (cs.valid_key_sizes.empty()) {
            key_info = std::to_string(cs.min_key) + "-" +
                       std::to_string(cs.max_key) + " (variable)";
        } else {
            for (size_t i = 0; i < cs.valid_key_sizes.size(); i++) {
                if (i > 0) key_info += ", ";
                key_info += std::to_string(cs.valid_key_sizes[i]);
            }
        }
        std::string type_str = cs.is_stream ? "stream" : "block";
        std::string size_info;
        if (cs.is_stream)
            size_info = "iv=" + std::to_string(cs.iv_size) + "B";
        else
            size_info = std::to_string(cs.block_size) + "B";
        char line[128];
        snprintf(line, sizeof(line), "%-18s%-12s%-8s%-25s%s\n",
                 cs.name.c_str(), "crypto++", type_str.c_str(),
                 key_info.c_str(), size_info.c_str());
        std::cout << line;
    }
}

static void list_modes_cmd() {
    std::cout << "Supported modes (Crypto++):\n\n";
    std::cout << "  Standard:\n";
    for (auto& m : BASE_MODES) {
        std::string note;
        if (m == "cfb") note = "  (8-bit feedback)";
        else if (m == "ncfb") note = "  (full-block feedback)";
        std::cout << "    " << m << note << "\n";
    }
    std::cout << "\n  CFB variants (feedback size in bits):\n";
    for (auto& m : CFB_MODES) {
        std::cout << "    " << m << "\n";
    }
    std::cout << "\n  Note: cfb-N modes are pruned when feedback > cipher block size.\n";
    std::cout << "  cfb-8 = cfb (8-bit). ncfb = cfb at full block size.\n";
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[]) {
    Options opts = parse_args(argc, argv);

    if (opts.list_ciphers) {
        list_ciphers_cmd();
        return 0;
    }
    if (opts.list_modes) {
        list_modes_cmd();
        return 0;
    }

    if (opts.ct_path.empty() || opts.wl_path.empty()) {
        std::cout << "Usage: cryptopp_brute --ct <file> --wl <file> [options]\n"
                  << "       cryptopp_brute --list-ciphers\n"
                  << "       cryptopp_brute --list-modes\n"
                  << "\nOptions:\n"
                  << "  --ct <file>              Ciphertext file (required)\n"
                  << "  --wl <file>              Wordlist file (required)\n"
                  << "  --ivs <file>             IV list file (optional)\n"
                  << "  --encoding <hex|base64|auto>  Ciphertext encoding (default: auto)\n"
                  << "  --ciphers <list|all>     Comma-separated cipher names (default: all)\n"
                  << "  --modes <list|all>       Comma-separated mode names (default: all)\n"
                  << "  --threshold <float>      Min ASCII score 0.0-1.0 (default: 0.70)\n"
                  << "  --top <int>              Top N results to keep (default: 50)\n"
                  << "  --key-format <raw|hex|base64> Wordlist key format (default: raw)\n"
                  << "  --iv-format <raw|hex>    IV list format (default: hex)\n"
                  << "  --reverse                Test reversed ciphertext\n"
                  << "  --caesar                 Test Caesar rotations\n"
                  << "  --char-shift             Test cyclic char shifts\n"
                  << "  --reverse-key            Test reversed keys\n"
                  << "  --list-ciphers           List supported ciphers and exit\n"
                  << "  --list-modes             List supported modes and exit\n";
        return 1;
    }

    // ── Build dispatch map ───────────────────────────────────────────────
    auto dispatch = build_dispatch_map();

    // ── Load ciphertext ──────────────────────────────────────────────────
    std::string ct_raw = read_file(opts.ct_path);
    if (ct_raw.empty()) {
        std::cout << "[ERROR] Ciphertext file not found or empty: "
                  << opts.ct_path << "\n";
        return 1;
    }
    std::string ct_trimmed = trim(ct_raw);

    std::string enc_used = opts.encoding;
    if (enc_used == "auto") {
        enc_used = detect_encoding(ct_trimmed);
        info("Auto-detected encoding: " + enc_used);
    }

    auto ct_variants = generate_ct_variants(ct_trimmed, enc_used,
                                            opts.do_reverse, opts.do_caesar,
                                            opts.do_char_shift);
    size_t variant_count = ct_variants.size();

    if (variant_count == 0) {
        std::cout << "[ERROR] Failed to decode ciphertext with encoding: "
                  << enc_used << "\n";
        return 1;
    }

    size_t ct_len = ct_variants[0].data.size();
    info("Loaded ciphertext: " + std::to_string(ct_len) + " bytes (" + enc_used + ")");
    if (variant_count > 1) {
        std::string names;
        for (size_t i = 0; i < std::min(variant_count, (size_t)8); i++) {
            if (i > 0) names += ", ";
            names += ct_variants[i].label;
        }
        if (variant_count > 8) names += "...";
        info("Generated " + std::to_string(variant_count) + " ciphertext variants: " + names);
    }

    // ── Load wordlist (count lines) ──────────────────────────────────────
    {
        std::ifstream test_wl(opts.wl_path);
        if (!test_wl.is_open()) {
            std::cout << "[ERROR] Wordlist file not found: " << opts.wl_path << "\n";
            return 1;
        }
    }

    size_t key_count = 0;
    {
        std::ifstream wl(opts.wl_path);
        std::string line;
        while (std::getline(wl, line)) key_count++;
    }
    size_t key_multiplier = opts.reverse_key ? 2 : 1;
    std::string key_info = "Wordlist: " + std::to_string(key_count) +
                           " keys (format: " + opts.key_format + ")";
    if (opts.reverse_key)
        key_info += " + reversed = " + std::to_string(key_count * 2) + " effective keys";
    info(key_info);

    // ── Load IVs ─────────────────────────────────────────────────────────
    std::vector<std::string> ivs;
    if (!opts.ivs_path.empty()) {
        std::ifstream ivf(opts.ivs_path);
        if (ivf.is_open()) {
            std::string line;
            while (std::getline(ivf, line)) {
                line = trim(line);
                if (line.empty()) continue;
                if (opts.iv_format == "hex") {
                    std::string decoded = hex_to_bytes(line);
                    if (!decoded.empty()) ivs.push_back(decoded);
                } else {
                    ivs.push_back(line);
                }
            }
            info("Loaded " + std::to_string(ivs.size()) + " IVs from file");
        }
    }
    if (ivs.empty()) {
        ivs.push_back(std::string(32, '\0'));
        info("Using all-zeros IV (default)");
    }

    // ── Resolve cipher & mode lists ──────────────────────────────────────
    std::vector<const CipherSpec*> cipher_list;
    if (opts.ciphers_arg == "all") {
        for (auto& cs : CIPHER_SPECS)
            cipher_list.push_back(&cs);
    } else {
        for (auto& name : split_comma(opts.ciphers_arg)) {
            auto cs = find_cipher_spec(name);
            if (cs) {
                cipher_list.push_back(cs);
            } else {
                std::cout << "[WARN] Unknown cipher '" << name << "' — skipping\n";
            }
        }
    }

    std::vector<std::string> mode_list;
    if (opts.modes_arg == "all") {
        mode_list = ALL_MODES;
    } else {
        for (auto& name : split_comma(opts.modes_arg)) {
            bool found = false;
            for (auto& m : ALL_MODES) {
                if (m == name) { found = true; break; }
            }
            if (found) {
                mode_list.push_back(name);
            } else {
                std::cout << "[WARN] Unknown mode '" << name << "' — skipping\n";
            }
        }
    }

    // ── Build combos & prune block-alignment ─────────────────────────────
    struct Combo {
        const CipherSpec* spec;
        std::string mode;
    };

    std::vector<Combo> combos;
    size_t pruned = 0;

    for (auto cs : cipher_list) {
        for (auto& m : mode_list) {
            // Stream ciphers only use "stream" mode
            if (cs->is_stream && m != "stream") continue;
            // Block ciphers skip "stream" mode
            if (!cs->is_stream && m == "stream") continue;

            // Block alignment check for ECB/CBC
            if (m == "ecb" || m == "cbc") {
                if (ct_len % cs->block_size != 0) {
                    pruned++;
                    continue;
                }
            }
            // CFB feedback size check: feedback cannot exceed block size
            int fb = parse_cfb_feedback(m);
            if (fb > 0 && (size_t)fb > cs->block_size) {
                pruned++;
                continue;
            }
            combos.push_back({cs, m});
        }
    }

    if (pruned > 0) {
        info("Pruned " + std::to_string(pruned) +
             " combos (block alignment / CFB feedback > block size)");
    }

    size_t combo_count = combos.size();
    size_t iv_count = ivs.size();
    size_t effective_keys = key_count * key_multiplier;
    uint64_t total = (uint64_t)variant_count * combo_count * effective_keys * iv_count;

    {
        // Format total with commas
        std::string total_str = std::to_string(total);
        std::string formatted;
        int count = 0;
        for (int i = (int)total_str.size() - 1; i >= 0; i--) {
            if (count > 0 && count % 3 == 0) formatted = "," + formatted;
            formatted = total_str[i] + formatted;
            count++;
        }
        info("Testing " + std::to_string(variant_count) + " variants x " +
             std::to_string(combo_count) + " cipher+mode combos x " +
             std::to_string(effective_keys) + " keys x " +
             std::to_string(iv_count) + " IVs = " + formatted + " combos");
    }

    // ── Brute force loop ─────────────────────────────────────────────────
    double threshold = opts.threshold;
    int top_n = opts.top;
    std::vector<HitResult> results;
    uint64_t tested = 0;
    auto start_time = std::chrono::steady_clock::now();
    double last_progress = 0.0;

    for (auto& variant : ct_variants) {
        if (variant_count > 1)
            info("Testing variant: " + variant.label + " (" +
                 std::to_string(variant.data.size()) + " bytes)");

        for (auto& combo : combos) {
            auto cs = combo.spec;
            auto& mode = combo.mode;
            auto it = dispatch.find(cs->name);
            if (it == dispatch.end()) continue;
            auto& decrypt_fn = it->second;

            // Open wordlist
            std::ifstream wl(opts.wl_path);
            if (!wl.is_open()) continue;

            std::string line;
            while (std::getline(wl, line)) {
                // Strip \r\n
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
                    line.pop_back();
                if (line.empty()) continue;

                // Decode key
                std::string raw_key;
                if (opts.key_format == "hex") {
                    raw_key = hex_to_bytes(line);
                    if (raw_key.empty()) {
                        tested += iv_count * key_multiplier;
                        continue;
                    }
                } else if (opts.key_format == "base64") {
                    std::string trimmed_line = trim(line);
                    raw_key = base64_decode(trimmed_line);
                    if (raw_key.empty()) {
                        tested += iv_count * key_multiplier;
                        continue;
                    }
                } else {
                    raw_key = line;
                }

                // Build key candidates
                struct KeyCandidate {
                    std::string key;
                    bool reversed;
                };
                std::vector<KeyCandidate> key_candidates;
                key_candidates.push_back({raw_key, false});
                if (opts.reverse_key) {
                    std::string rev(raw_key.rbegin(), raw_key.rend());
                    if (rev != raw_key)
                        key_candidates.push_back({rev, true});
                }

                for (auto& kc : key_candidates) {
                    std::string fitted_key = fit_key(kc.key, *cs);

                    for (auto& raw_iv : ivs) {
                        tested++;

                        size_t iv_req = cs->is_stream ? cs->iv_size : cs->block_size;
                        std::string fitted_iv = fit_iv(raw_iv, iv_req);
                        if (mode == "ecb")
                            fitted_iv = "";

                        std::string plaintext;
                        bool ok = decrypt_fn(mode, variant.data, fitted_key, fitted_iv, plaintext);

                        if (!ok || plaintext.empty()) continue;

                        double score = score_printable(plaintext);

                        if (score >= threshold) {
                            std::string key_hex = bytes_to_hex(fitted_key);
                            std::string iv_hex = bytes_to_hex(fitted_iv);
                            std::string preview = safe_preview(plaintext);
                            std::string key_ascii = safe_preview(kc.key, 40);
                            if (kc.reversed) key_ascii += " (rev)";

                            HitResult hit;
                            hit.score = std::round(score * 10000.0) / 100.0;
                            hit.cipher = cs->name;
                            hit.mode = mode;
                            hit.variant = variant.label;
                            hit.key_ascii = key_ascii;
                            hit.key_hex = key_hex;
                            hit.iv_hex = iv_hex;
                            hit.preview = preview;

                            char hit_line[1024];
                            snprintf(hit_line, sizeof(hit_line),
                                     "[HIT] score=%.2f cipher=%s mode=%s variant=%s "
                                     "key_hex=%s iv_hex=%s preview=\"%s\"",
                                     hit.score, cs->name.c_str(), mode.c_str(),
                                     variant.label.c_str(), key_hex.c_str(),
                                     iv_hex.c_str(), preview.c_str());
                            std::cout << hit_line << "\n";
                            std::cout.flush();

                            results.push_back(hit);
                            std::sort(results.begin(), results.end(), cmp_score_desc);
                            if ((int)results.size() > top_n)
                                results.resize(top_n);
                        }

                        // Progress
                        if (total > 0) {
                            double pct = static_cast<double>(tested) / total;
                            if (pct - last_progress >= 0.001 || tested == total) {
                                emit_progress(pct);
                                last_progress = pct;
                            }
                        }
                    }
                }
            }
        }
    }

    auto end_time = std::chrono::steady_clock::now();
    double elapsed = std::chrono::duration<double>(end_time - start_time).count();
    elapsed = std::round(elapsed * 100.0) / 100.0;

    // ── Final output ─────────────────────────────────────────────────────
    size_t hit_count = results.size();
    std::cout << "[DONE] " << hit_count << " results above threshold ("
              << (threshold * 100) << "%)\n";

    std::sort(results.begin(), results.end(), cmp_score_desc);

    // Hand-built JSON
    std::ostringstream json;
    json << "{\n";
    json << "    \"results\": [\n";
    for (size_t i = 0; i < results.size(); i++) {
        auto& r = results[i];
        json << "        {\n";
        json << "            \"score\": " << std::fixed << std::setprecision(2) << r.score << ",\n";
        json << "            \"cipher\": \"" << json_escape(r.cipher) << "\",\n";
        json << "            \"mode\": \"" << json_escape(r.mode) << "\",\n";
        json << "            \"variant\": \"" << json_escape(r.variant) << "\",\n";
        json << "            \"key_ascii\": \"" << json_escape(r.key_ascii) << "\",\n";
        json << "            \"key_hex\": \"" << json_escape(r.key_hex) << "\",\n";
        json << "            \"iv_hex\": \"" << json_escape(r.iv_hex) << "\",\n";
        json << "            \"preview\": \"" << json_escape(r.preview) << "\"\n";
        json << "        }";
        if (i + 1 < results.size()) json << ",";
        json << "\n";
    }
    json << "    ],\n";
    json << "    \"total_tested\": " << tested << ",\n";
    json << "    \"elapsed\": " << std::fixed << std::setprecision(2) << elapsed << "\n";
    json << "}\n";

    std::cout << "[RESULTS_JSON]\n" << json.str();
    std::cout.flush();

    // Format tested count with commas
    std::string tested_str = std::to_string(tested);
    std::string formatted_tested;
    int count = 0;
    for (int i = (int)tested_str.size() - 1; i >= 0; i--) {
        if (count > 0 && count % 3 == 0) formatted_tested = "," + formatted_tested;
        formatted_tested = tested_str[i] + formatted_tested;
        count++;
    }

    info("Completed in " + std::to_string(elapsed) + "s — tested " +
         formatted_tested + " combinations");

    return 0;
}
