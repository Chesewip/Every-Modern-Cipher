#!/usr/bin/env python3
"""
PyCryptodome Brute-Force Cipher Testing Tool

Tests ciphertext against PyCryptodome-supported cipher algorithms
using a wordlist and optional IV list. Scores results by printable ASCII %.

Usage: python pycrypto_brute.py --ct <file> --wl <file> [options]
"""

import sys
import os
import json
import time
import re
import binascii

from Crypto.Cipher import AES, DES, DES3, Blowfish, CAST, ARC2, ARC4, Salsa20, ChaCha20

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def stderr(msg):
    print(msg, file=sys.stderr, flush=True)

def info(msg):
    print(f"[INFO] {msg}", flush=True)

def emit_progress(fraction):
    stderr(f"[PROGRESS] {fraction:.5f}")

def score_printable(data):
    if len(data) == 0:
        return 0.0
    printable = 0
    for b in data:
        if (0x20 <= b <= 0x7E) or b in (0x09, 0x0A, 0x0D):
            printable += 1
    return printable / len(data)

def safe_preview(data, max_len=80):
    out = []
    for b in data[:max_len]:
        if (0x20 <= b <= 0x7E) or b == 0x09:
            out.append(chr(b))
        else:
            out.append('.')
    return ''.join(out)

def bytes_to_hex(data):
    return binascii.hexlify(data).decode('ascii')

def hex_to_bytes(hex_str):
    hex_str = hex_str.strip()
    if len(hex_str) % 2 != 0:
        hex_str = '0' + hex_str
    try:
        return binascii.unhexlify(hex_str)
    except Exception:
        return None

# ---------------------------------------------------------------------------
# Encoding detection & ciphertext decoding
# ---------------------------------------------------------------------------

def detect_encoding(data):
    import base64
    trimmed = data.strip()
    if re.match(r'^[0-9a-fA-F]+$', trimmed) and len(trimmed) % 2 == 0:
        decoded = hex_to_bytes(trimmed)
        if decoded is not None:
            return 'hex'
    try:
        decoded = base64.b64decode(trimmed, validate=True)
        if len(decoded) > 0:
            return 'base64'
    except Exception:
        pass
    return 'hex'

def decode_ciphertext(raw, encoding):
    import base64
    trimmed = raw.strip()
    if encoding == 'auto':
        encoding = detect_encoding(trimmed)
        info(f"Auto-detected encoding: {encoding}")
    if encoding == 'hex':
        decoded = hex_to_bytes(trimmed)
        if decoded is None:
            print("[ERROR] Invalid hex data in ciphertext file")
            sys.exit(1)
        return decoded, 'hex'
    else:
        try:
            decoded = base64.b64decode(trimmed, validate=True)
        except Exception:
            print("[ERROR] Invalid base64 data in ciphertext file")
            sys.exit(1)
        return decoded, 'base64'

# ---------------------------------------------------------------------------
# Caesar rotation & reverse on encoded strings
# ---------------------------------------------------------------------------

def caesar_rotate_hex(s, shift):
    alphabet = '0123456789abcdef'
    s = s.lower()
    out = []
    for ch in s:
        pos = alphabet.find(ch)
        if pos >= 0:
            out.append(alphabet[(pos + shift) % 16])
        else:
            out.append(ch)
    return ''.join(out)

def caesar_rotate_base64(s, shift):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    out = []
    for ch in s:
        pos = alphabet.find(ch)
        if pos >= 0:
            out.append(alphabet[(pos + shift) % 64])
        else:
            out.append(ch)
    return ''.join(out)

def try_decode(encoded, encoding):
    import base64
    if encoding == 'hex':
        trimmed = encoded.strip().lower()
        if not re.match(r'^[0-9a-f]+$', trimmed):
            return None
        if len(trimmed) % 2 != 0:
            return None
        return hex_to_bytes(trimmed)
    else:
        try:
            decoded = base64.b64decode(encoded, validate=True)
            if len(decoded) == 0:
                return None
            return decoded
        except Exception:
            return None

def generate_ct_variants(ct_raw_encoded, encoding, do_reverse, do_caesar, do_char_shift=False):
    trimmed = ct_raw_encoded.strip()

    # Phase 1: Build (label, encoded_string) pairs
    enc_variants = [('original', trimmed)]

    if do_reverse:
        enc_variants.append(('reversed', trimmed[::-1]))

    if do_caesar:
        max_shift = 15 if encoding == 'hex' else 63
        for shift in range(1, max_shift + 1):
            if encoding == 'hex':
                rotated = caesar_rotate_hex(trimmed, shift)
            else:
                rotated = caesar_rotate_base64(trimmed, shift)
            enc_variants.append((f'caesar-{shift}', rotated))

            if do_reverse:
                enc_variants.append((f'rev+caesar-{shift}', rotated[::-1]))

    # Phase 2: Character-level cyclic shifts on encoded strings
    if do_char_shift:
        base_count = len(enc_variants)
        for vi in range(base_count):
            enc = enc_variants[vi][1]
            for s in range(1, len(enc)):
                enc_variants.append((
                    enc_variants[vi][0] + f'+shift-{s}',
                    enc[s:] + enc[:s]
                ))

    # Phase 3: Decode all variants
    variants = []
    for label, enc in enc_variants:
        decoded = try_decode(enc, encoding)
        if decoded is not None:
            variants.append((label, decoded))

    return variants

# ---------------------------------------------------------------------------
# Cipher definitions
# ---------------------------------------------------------------------------

BLOCK_CIPHERS = {
    'aes-128-pc':  {'module': AES,      'key_size': 16, 'block_size': 16},
    'aes-192-pc':  {'module': AES,      'key_size': 24, 'block_size': 16},
    'aes-256-pc':  {'module': AES,      'key_size': 32, 'block_size': 16},
    'des-pc':      {'module': DES,      'key_size': 8,  'block_size': 8},
    '3des-pc':     {'module': DES3,     'key_size': 24, 'block_size': 8},
    'blowfish-pc': {'module': Blowfish, 'key_size': None, 'block_size': 8,
                    'min_key': 4, 'max_key': 56},
    'cast5-pc':    {'module': CAST,     'key_size': None, 'block_size': 8,
                    'min_key': 5, 'max_key': 16},
    'rc2-pc':      {'module': ARC2,     'key_size': None, 'block_size': 8,
                    'min_key': 5, 'max_key': 128},
}

STREAM_CIPHERS = {
    'salsa20':  {'module': Salsa20,  'key_sizes': [16, 32], 'nonce_size': 8},
    'chacha20': {'module': ChaCha20, 'key_sizes': [32],     'nonce_size': 8},
    'rc4-pc':   {'module': ARC4,     'key_sizes': None,     'min_key': 1, 'max_key': 256},
}

ALL_CIPHERS = {**BLOCK_CIPHERS, **STREAM_CIPHERS}

# Modes for block ciphers
BLOCK_MODES = {
    'ecb':  'ecb',
    'cbc':  'cbc',
    'cfb':  'cfb',    # 8-bit CFB (matches mcrypt 'cfb')
    'ncfb': 'ncfb',   # Full-block CFB (matches mcrypt 'ncfb')
    'nofb': 'nofb',   # Full-block OFB (matches mcrypt 'nofb')
    'ctr':  'ctr',
}

STREAM_MODES = {
    'stream': 'stream',
}

ALL_MODES = {**BLOCK_MODES, **STREAM_MODES}

# ---------------------------------------------------------------------------
# Key / IV fitting
# ---------------------------------------------------------------------------

def fit_key_block(key, cipher_def):
    """Pad or truncate key to match block cipher requirements."""
    key_size = cipher_def.get('key_size')
    if key_size is not None:
        # Fixed key size
        kl = len(key)
        if kl < key_size:
            return key + b'\x00' * (key_size - kl)
        elif kl > key_size:
            return key[:key_size]
        return key
    else:
        # Variable key size
        min_k = cipher_def['min_key']
        max_k = cipher_def['max_key']
        kl = len(key)
        if kl < min_k:
            return key + b'\x00' * (min_k - kl)
        elif kl > max_k:
            return key[:max_k]
        return key

def fit_key_stream(key, cipher_def):
    """Pad or truncate key for stream cipher."""
    key_sizes = cipher_def.get('key_sizes')
    if key_sizes is None:
        # Variable (RC4)
        min_k = cipher_def['min_key']
        max_k = cipher_def['max_key']
        kl = len(key)
        if kl < min_k:
            return key + b'\x00' * (min_k - kl)
        elif kl > max_k:
            return key[:max_k]
        return key
    else:
        # Fixed sizes — pick smallest that fits
        kl = len(key)
        key_sizes_sorted = sorted(key_sizes)
        target = key_sizes_sorted[-1]  # default to largest
        for s in key_sizes_sorted:
            if kl <= s:
                target = s
                break
        if kl < target:
            return key + b'\x00' * (target - kl)
        elif kl > target:
            return key[:target]
        return key

def _fit_key_to_size(key, target):
    """Pad or truncate key to exact target size."""
    kl = len(key)
    if kl < target:
        return key + b'\x00' * (target - kl)
    elif kl > target:
        return key[:target]
    return key


def _repeat_key_to_size(key, target):
    """Repeat key cyclically to fill target size."""
    kl = len(key)
    if kl == 0:
        return b'\x00' * target
    if kl >= target:
        return key[:target]
    repeats = (target + kl - 1) // kl
    return (key * repeats)[:target]


def _add_repeat_variants(results, key, repeat_key):
    """If repeat_key is on and key was padded, add repeated variant."""
    if not repeat_key:
        return results
    out = []
    for fitted in results:
        out.append(fitted)
        if len(key) < len(fitted):
            rep = _repeat_key_to_size(key, len(fitted))
            if rep != fitted:
                out.append(rep)
    return out


def get_all_fitted_keys(key, cipher_def, is_stream, all_sizes, repeat_key):
    """Return list of fitted keys. Multiple entries when all_sizes=True and cipher has multiple fixed sizes."""
    if not all_sizes:
        if is_stream:
            results = [fit_key_stream(key, cipher_def)]
        else:
            results = [fit_key_block(key, cipher_def)]
        return _add_repeat_variants(results, key, repeat_key)

    if is_stream:
        key_sizes = cipher_def.get('key_sizes')
        if key_sizes is not None and len(key_sizes) > 1:
            results = [_fit_key_to_size(key, s) for s in sorted(key_sizes)]
        else:
            results = [fit_key_stream(key, cipher_def)]
        return _add_repeat_variants(results, key, repeat_key)
    else:
        results = [fit_key_block(key, cipher_def)]
        return _add_repeat_variants(results, key, repeat_key)


def fit_iv_block(iv, block_size, mode):
    """Fit IV to required size for block cipher mode."""
    if mode == 'ecb':
        return b''
    iv_size = block_size
    if mode == 'ctr':
        iv_size = block_size  # nonce/IV for CTR
    iv_len = len(iv)
    if iv_len < iv_size:
        return iv + b'\x00' * (iv_size - iv_len)
    elif iv_len > iv_size:
        return iv[:iv_size]
    return iv

def fit_iv_stream(iv, cipher_def):
    """Fit IV/nonce for stream cipher."""
    nonce_size = cipher_def.get('nonce_size', 0)
    if nonce_size == 0:
        return b''
    iv_len = len(iv)
    if iv_len < nonce_size:
        return iv + b'\x00' * (nonce_size - iv_len)
    elif iv_len > nonce_size:
        return iv[:nonce_size]
    return iv

# ---------------------------------------------------------------------------
# Decryption
# ---------------------------------------------------------------------------

def try_decrypt_block(ciphertext, cipher_def, mode, key, iv):
    """Attempt block cipher decryption. Returns plaintext bytes or None."""
    mod = cipher_def['module']
    bs = cipher_def['block_size']

    try:
        if mode == 'ecb':
            if len(ciphertext) % bs != 0:
                return None
            cipher = mod.new(key, mod.MODE_ECB)
        elif mode == 'cbc':
            if len(ciphertext) % bs != 0:
                return None
            cipher = mod.new(key, mod.MODE_CBC, iv=iv)
        elif mode == 'cfb':
            # 8-bit CFB (matches mcrypt cfb)
            cipher = mod.new(key, mod.MODE_CFB, iv=iv, segment_size=8)
        elif mode == 'ncfb':
            # Full-block CFB (matches mcrypt ncfb)
            cipher = mod.new(key, mod.MODE_CFB, iv=iv, segment_size=bs * 8)
        elif mode == 'nofb':
            # Full-block OFB
            cipher = mod.new(key, mod.MODE_OFB, iv=iv)
        elif mode == 'ctr':
            # CTR mode — use IV as initial nonce
            cipher = mod.new(key, mod.MODE_CTR, nonce=iv[:bs // 2],
                             initial_value=int.from_bytes(iv[bs // 2:], 'big'))
        else:
            return None

        return cipher.decrypt(ciphertext)
    except (ValueError, KeyError):
        return None

def try_decrypt_stream(ciphertext, cipher_def, key, nonce):
    """Attempt stream cipher decryption. Returns plaintext bytes or None."""
    mod = cipher_def['module']

    try:
        if mod == ARC4:
            cipher = mod.new(key)
        else:
            cipher = mod.new(key=key, nonce=nonce)
        return cipher.decrypt(ciphertext)
    except (ValueError, KeyError):
        return None

# ---------------------------------------------------------------------------
# --list-ciphers / --list-modes
# ---------------------------------------------------------------------------

def list_ciphers():
    print("Supported ciphers (PyCryptodome):\n")
    print(f"{'Name':<16}{'Engine':<14}{'Type':<10}{'Key size':<25}{'Block size'}")
    print("-" * 80)

    for name, d in BLOCK_CIPHERS.items():
        ks = d.get('key_size')
        if ks is not None:
            key_info = str(ks)
        else:
            key_info = f"{d['min_key']}-{d['max_key']} (variable)"
        block_info = f"{d['block_size']}B"
        print(f"{name:<16}{'pycryptodome':<14}{'block':<10}{key_info:<25}{block_info}")

    for name, d in STREAM_CIPHERS.items():
        key_sizes = d.get('key_sizes')
        if key_sizes is None:
            key_info = f"{d['min_key']}-{d['max_key']} (variable)"
        else:
            key_info = ', '.join(str(s) for s in key_sizes)
        nonce_info = d.get('nonce_size', 0)
        extra = f"  nonce={nonce_info}B" if nonce_info else ""
        print(f"{name:<16}{'pycryptodome':<14}{'stream':<10}{key_info:<25}stream{extra}")

def list_modes():
    print("Supported modes (PyCryptodome):\n")
    for name in ALL_MODES:
        print(f"  {name}")

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        description="PyCryptodome Brute-Force Cipher Testing Tool")
    parser.add_argument('--ct', help='Ciphertext file')
    parser.add_argument('--wl', help='Wordlist file')
    parser.add_argument('--ivs', help='IV list file')
    parser.add_argument('--encoding', default='auto',
                        choices=['auto', 'hex', 'base64'])
    parser.add_argument('--ciphers', default='all',
                        help='Comma-separated cipher names or "all"')
    parser.add_argument('--modes', default='all',
                        help='Comma-separated mode names or "all"')
    parser.add_argument('--threshold', type=float, default=0.70)
    parser.add_argument('--top', type=int, default=50)
    parser.add_argument('--key-format', default='raw', choices=['raw', 'hex', 'base64'])
    parser.add_argument('--iv-format', default='hex', choices=['raw', 'hex'])
    parser.add_argument('--list-ciphers', action='store_true')
    parser.add_argument('--list-modes', action='store_true')
    parser.add_argument('--reverse', action='store_true')
    parser.add_argument('--caesar', action='store_true')
    parser.add_argument('--char-shift', action='store_true')
    parser.add_argument('--reverse-key', action='store_true')
    parser.add_argument('--all-key-sizes', action='store_true')
    parser.add_argument('--repeat-key', action='store_true')

    return parser.parse_args()

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    args = parse_args()

    if args.list_ciphers:
        list_ciphers()
        sys.exit(0)
    if args.list_modes:
        list_modes()
        sys.exit(0)

    if not args.ct or not args.wl:
        print("Usage: python pycrypto_brute.py --ct <file> --wl <file> [options]")
        print("       python pycrypto_brute.py --list-ciphers")
        sys.exit(1)

    # ── Load ciphertext ────────────────────────────────────────────────
    if not os.path.isfile(args.ct):
        print(f"[ERROR] Ciphertext file not found: {args.ct}")
        sys.exit(1)

    with open(args.ct, 'r') as f:
        ct_raw = f.read()
    ct_trimmed = ct_raw.strip()

    enc_used = args.encoding
    if enc_used == 'auto':
        enc_used = detect_encoding(ct_trimmed)
        info(f"Auto-detected encoding: {enc_used}")

    ct_variants = generate_ct_variants(ct_trimmed, enc_used,
                                       args.reverse, args.caesar,
                                       args.char_shift)
    variant_count = len(ct_variants)

    if variant_count == 0:
        print(f"[ERROR] Failed to decode ciphertext with encoding: {enc_used}")
        sys.exit(1)

    ct_len = len(ct_variants[0][1])
    info(f"Loaded ciphertext: {ct_len} bytes ({enc_used})")
    if variant_count > 1:
        names = [v[0] for v in ct_variants[:8]]
        info(f"Generated {variant_count} ciphertext variants: "
             f"{', '.join(names)}{'...' if variant_count > 8 else ''}")

    # ── Load wordlist ──────────────────────────────────────────────────
    if not os.path.isfile(args.wl):
        print(f"[ERROR] Wordlist file not found: {args.wl}")
        sys.exit(1)

    with open(args.wl, 'r', errors='replace') as f:
        key_count = sum(1 for _ in f)
    key_multiplier = 2 if args.reverse_key else 1
    info(f"Wordlist: {key_count} keys (format: {args.key_format})"
         + (f" + reversed = {key_count * 2} effective keys" if args.reverse_key else ""))

    # ── Load IVs ───────────────────────────────────────────────────────
    ivs = []
    if args.ivs and os.path.isfile(args.ivs):
        with open(args.ivs, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if args.iv_format == 'hex':
                    decoded = hex_to_bytes(line)
                    if decoded is not None:
                        ivs.append(decoded)
                else:
                    ivs.append(line.encode('latin-1'))
        info(f"Loaded {len(ivs)} IVs from file")
    else:
        ivs.append(b'\x00' * 32)
        info("Using all-zeros IV (default)")

    # ── Resolve ciphers & modes ────────────────────────────────────────
    if args.ciphers == 'all':
        cipher_list = dict(ALL_CIPHERS)
    else:
        cipher_list = {}
        for name in args.ciphers.split(','):
            name = name.strip()
            if name in ALL_CIPHERS:
                cipher_list[name] = ALL_CIPHERS[name]
            else:
                print(f"[WARN] Unknown cipher '{name}' — skipping")

    if args.modes == 'all':
        mode_list = dict(ALL_MODES)
    else:
        mode_list = {}
        for name in args.modes.split(','):
            name = name.strip()
            if name in ALL_MODES:
                mode_list[name] = ALL_MODES[name]
            else:
                print(f"[WARN] Unknown mode '{name}' — skipping")

    # ── Build combos ───────────────────────────────────────────────────
    combos = []

    for c_name, c_def in cipher_list.items():
        is_stream = c_name in STREAM_CIPHERS

        for m_name in mode_list:
            if is_stream and m_name != 'stream':
                continue
            if not is_stream and m_name == 'stream':
                continue

            # Block-alignment pre-check for ECB/CBC
            if not is_stream and m_name in ('ecb', 'cbc'):
                bs = c_def['block_size']
                if ct_len % bs != 0:
                    continue

            combos.append({
                'cipher': c_name,
                'cipher_def': c_def,
                'mode': m_name,
                'is_stream': is_stream,
            })

    combo_count = len(combos)
    iv_count = len(ivs)
    effective_keys = key_count * key_multiplier
    total = variant_count * combo_count * effective_keys * iv_count

    info(f"Testing {variant_count} variants x {combo_count} cipher+mode combos "
         f"x {effective_keys} keys x {iv_count} IVs = {total:,} combos")

    # ── Brute force loop ───────────────────────────────────────────────
    threshold = args.threshold
    top_n = args.top
    results = []
    tested = 0
    start_time = time.time()
    last_progress = 0.0

    for v_label, ciphertext in ct_variants:
        if variant_count > 1:
            info(f"Testing variant: {v_label} ({len(ciphertext)} bytes)")

        for combo in combos:
            c_name = combo['cipher']
            c_def = combo['cipher_def']
            m_name = combo['mode']
            is_stream = combo['is_stream']

            with open(args.wl, 'r', errors='replace') as fh:
                for line in fh:
                    line = line.rstrip('\r\n')
                    if not line:
                        continue

                    # Decode key
                    if args.key_format == 'hex':
                        raw_key = hex_to_bytes(line)
                        if raw_key is None:
                            tested += iv_count * key_multiplier
                            continue
                    elif args.key_format == 'base64':
                        import base64 as b64mod
                        try:
                            raw_key = b64mod.b64decode(line.strip(), validate=True)
                        except Exception:
                            tested += iv_count * key_multiplier
                            continue
                    else:
                        raw_key = line.encode('latin-1')

                    # Build key candidates
                    key_candidates = [(raw_key, False)]
                    if args.reverse_key:
                        rev_key = raw_key[::-1]
                        if rev_key != raw_key:
                            key_candidates.append((rev_key, True))

                    for candidate_key, is_reversed in key_candidates:
                        # Fit key — may return multiple sizes with --all-key-sizes
                        fitted_keys = get_all_fitted_keys(
                            candidate_key, c_def, is_stream,
                            args.all_key_sizes, args.repeat_key)

                        for fitted_key in fitted_keys:
                            for raw_iv in ivs:
                                tested += 1

                                # Decrypt
                                if is_stream:
                                    fitted_iv = fit_iv_stream(raw_iv, c_def)
                                    plaintext = try_decrypt_stream(
                                        ciphertext, c_def, fitted_key, fitted_iv)
                                else:
                                    fitted_iv = fit_iv_block(
                                        raw_iv, c_def['block_size'], m_name)
                                    plaintext = try_decrypt_block(
                                        ciphertext, c_def, m_name,
                                        fitted_key, fitted_iv)

                                if plaintext is None or len(plaintext) == 0:
                                    continue

                                score = score_printable(plaintext)

                                if score >= threshold:
                                    key_hex = bytes_to_hex(fitted_key)
                                    iv_hex = bytes_to_hex(fitted_iv)
                                    preview = safe_preview(plaintext)
                                    key_ascii = safe_preview(candidate_key, 40)
                                    key_note = ' (rev)' if is_reversed else ''

                                    hit = {
                                        'score': round(score * 100, 2),
                                        'cipher': c_name,
                                        'mode': m_name,
                                        'variant': v_label,
                                        'key_ascii': key_ascii + key_note,
                                        'key_hex': key_hex,
                                        'iv_hex': iv_hex,
                                        'preview': preview,
                                    }

                                    print(f'[HIT] score={hit["score"]:.2f} '
                                          f'cipher={c_name} mode={m_name} '
                                          f'variant={v_label} key_hex={key_hex} '
                                          f'iv_hex={iv_hex} preview="{preview}"',
                                          flush=True)

                                    results.append(hit)
                                    results.sort(key=lambda x: x['score'],
                                                 reverse=True)
                                    if len(results) > top_n:
                                        results = results[:top_n]

                                # Progress
                                if total > 0:
                                    pct = tested / total
                                    if pct - last_progress >= 0.001 or tested == total:
                                        emit_progress(pct)
                                        last_progress = pct

    elapsed = round(time.time() - start_time, 2)

    # ── Results ────────────────────────────────────────────────────────
    hit_count = len(results)
    print(f"[DONE] {hit_count} results above threshold "
          f"({threshold * 100:.0f}%)")

    results.sort(key=lambda x: x['score'], reverse=True)
    data = {
        'results': results,
        'total_tested': tested,
        'elapsed': elapsed,
    }
    print("[RESULTS_JSON]")
    print(json.dumps(data, indent=4))
    sys.stdout.flush()

    info(f"Completed in {elapsed}s — tested {tested:,} combinations")


if __name__ == '__main__':
    main()
