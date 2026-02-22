<?php
/**
 * mcrypt Brute-Force Cipher Testing Tool
 *
 * Tests ciphertext against all mcrypt-supported cipher algorithms
 * using a wordlist and optional IV list. Scores results by printable ASCII %.
 *
 * Usage: php mcrypt_brute.php --ct <file> --wl <file> [options]
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function stderr($msg) {
    fwrite(STDERR, $msg . "\n");
}

function info($msg) {
    echo "[INFO] $msg\n";
    flush();
}

function emit_progress($fraction) {
    stderr(sprintf("[PROGRESS] %.5f", $fraction));
}

function score_printable($data) {
    if (strlen($data) === 0) return 0.0;
    $printable = 0;
    $len = strlen($data);
    for ($i = 0; $i < $len; $i++) {
        $b = ord($data[$i]);
        // Printable ASCII (0x20-0x7E) plus tab, newline, CR
        if (($b >= 0x20 && $b <= 0x7E) || $b === 0x09 || $b === 0x0A || $b === 0x0D) {
            $printable++;
        }
    }
    return $printable / $len;
}

function safe_preview($data, $max = 80) {
    $out = '';
    $len = min(strlen($data), $max);
    for ($i = 0; $i < $len; $i++) {
        $b = ord($data[$i]);
        if (($b >= 0x20 && $b <= 0x7E) || $b === 0x09) {
            $out .= chr($b);
        } else {
            $out .= '.';
        }
    }
    return $out;
}

function bytes_to_hex($data) {
    return bin2hex($data);
}

function hex_to_bytes($hex) {
    $hex = trim($hex);
    if (strlen($hex) % 2 !== 0) {
        $hex = '0' . $hex;
    }
    return @hex2bin($hex);
}

function detect_encoding($data) {
    $trimmed = trim($data);
    // Check if valid hex (even length, all hex chars)
    if (preg_match('/^[0-9a-fA-F]+$/', $trimmed) && strlen($trimmed) % 2 === 0) {
        $decoded = hex_to_bytes($trimmed);
        if ($decoded !== false) return 'hex';
    }
    // Check if valid base64
    $decoded = @base64_decode($trimmed, true);
    if ($decoded !== false && strlen($decoded) > 0) {
        // Verify round-trip
        if (base64_encode($decoded) === $trimmed ||
            base64_encode($decoded) === rtrim($trimmed, '=') . str_repeat('=', (4 - strlen(rtrim($trimmed, '=')) % 4) % 4)) {
            return 'base64';
        }
    }
    return 'hex'; // fallback
}

function decode_ciphertext($raw, $encoding) {
    $trimmed = trim($raw);
    if ($encoding === 'auto') {
        $encoding = detect_encoding($trimmed);
        info("Auto-detected encoding: $encoding");
    }
    if ($encoding === 'hex') {
        $decoded = hex_to_bytes($trimmed);
        if ($decoded === false) {
            echo "[ERROR] Invalid hex data in ciphertext file\n";
            exit(1);
        }
        return [$decoded, 'hex'];
    } else {
        $decoded = base64_decode($trimmed, true);
        if ($decoded === false) {
            echo "[ERROR] Invalid base64 data in ciphertext file\n";
            exit(1);
        }
        return [$decoded, 'base64'];
    }
}

// ---------------------------------------------------------------------------
// Caesar rotation & reverse on encoded strings
// ---------------------------------------------------------------------------

function caesar_rotate_hex($str, $shift) {
    $alphabet = '0123456789abcdef';
    $str = strtolower($str);
    $out = '';
    $len = strlen($str);
    for ($i = 0; $i < $len; $i++) {
        $pos = strpos($alphabet, $str[$i]);
        if ($pos !== false) {
            $out .= $alphabet[($pos + $shift) % 16];
        } else {
            $out .= $str[$i];
        }
    }
    return $out;
}

function caesar_rotate_base64($str, $shift) {
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    $out = '';
    $len = strlen($str);
    for ($i = 0; $i < $len; $i++) {
        $pos = strpos($alphabet, $str[$i]);
        if ($pos !== false) {
            $out .= $alphabet[($pos + $shift) % 64];
        } else {
            $out .= $str[$i]; // keep '=' padding as-is
        }
    }
    return $out;
}

function try_decode($encoded, $encoding) {
    if ($encoding === 'hex') {
        $trimmed = strtolower(trim($encoded));
        if (!preg_match('/^[0-9a-f]+$/', $trimmed)) return false;
        if (strlen($trimmed) % 2 !== 0) return false;
        return @hex2bin($trimmed);
    } else {
        $decoded = @base64_decode($encoded, true);
        if ($decoded === false || strlen($decoded) === 0) return false;
        return $decoded;
    }
}

function generate_ct_variants($ct_raw_encoded, $encoding, $do_reverse, $do_caesar, $do_char_shift = false) {
    $trimmed = trim($ct_raw_encoded);

    // Phase 1: Build [label, encoded_string] pairs
    $enc_variants = [];
    $enc_variants[] = ['original', $trimmed];

    if ($do_reverse) {
        $enc_variants[] = ['reversed', strrev($trimmed)];
    }

    if ($do_caesar) {
        $max_shift = ($encoding === 'hex') ? 15 : 63;
        for ($shift = 1; $shift <= $max_shift; $shift++) {
            $rotated = ($encoding === 'hex')
                ? caesar_rotate_hex($trimmed, $shift)
                : caesar_rotate_base64($trimmed, $shift);
            $enc_variants[] = ["caesar-$shift", $rotated];

            if ($do_reverse) {
                $enc_variants[] = ["rev+caesar-$shift", strrev($rotated)];
            }
        }
    }

    // Phase 2: Character-level cyclic shifts on encoded strings
    if ($do_char_shift) {
        $base_count = count($enc_variants);
        for ($vi = 0; $vi < $base_count; $vi++) {
            $enc = $enc_variants[$vi][1];
            $len = strlen($enc);
            for ($s = 1; $s < $len; $s++) {
                $enc_variants[] = [
                    $enc_variants[$vi][0] . "+shift-$s",
                    substr($enc, $s) . substr($enc, 0, $s)
                ];
            }
        }
    }

    // Phase 3: Decode all variants
    $variants = [];
    foreach ($enc_variants as $ev) {
        $decoded = try_decode($ev[1], $encoding);
        if ($decoded !== false) {
            $variants[] = [$ev[0], $decoded];
        }
    }

    return $variants;
}

// ---------------------------------------------------------------------------
// Cipher/Mode definitions
// ---------------------------------------------------------------------------

$BLOCK_CIPHERS = [
    'blowfish'       => MCRYPT_BLOWFISH,
    'twofish'        => MCRYPT_TWOFISH,
    'des'            => MCRYPT_DES,
    '3des'           => MCRYPT_3DES,
    'saferplus'      => MCRYPT_SAFERPLUS,
    'loki97'         => MCRYPT_LOKI97,
    'gost'           => MCRYPT_GOST,
    'rc2'            => MCRYPT_RC2,
    'rijndael-128'   => MCRYPT_RIJNDAEL_128,
    'rijndael-192'   => MCRYPT_RIJNDAEL_192,
    'rijndael-256'   => MCRYPT_RIJNDAEL_256,
    'serpent'        => MCRYPT_SERPENT,
    'cast-128'       => MCRYPT_CAST_128,
    'cast-256'       => MCRYPT_CAST_256,
    'xtea'           => 'xtea',
    'blowfish-compat' => 'blowfish-compat',
];

$STREAM_CIPHERS = [
    'arcfour' => MCRYPT_ARCFOUR,
    'wake'    => MCRYPT_WAKE,
    'enigma'  => 'enigma',
];

$ALL_CIPHERS = array_merge($BLOCK_CIPHERS, $STREAM_CIPHERS);

$BLOCK_MODES = [
    'ecb'  => MCRYPT_MODE_ECB,
    'cbc'  => MCRYPT_MODE_CBC,
    'cfb'  => MCRYPT_MODE_CFB,
    'ofb'  => MCRYPT_MODE_OFB,
    'nofb' => MCRYPT_MODE_NOFB,
    'ncfb' => 'ncfb',
    'ctr'  => 'ctr',   // OpenSSL-only — mcrypt_module_open rejects it silently
];

$STREAM_MODE = [
    'stream' => MCRYPT_MODE_STREAM,
];

$ALL_MODES = array_merge($BLOCK_MODES, $STREAM_MODE);

// ---------------------------------------------------------------------------
// OpenSSL-only cipher definitions (Camellia, SEED, DESX)
// ---------------------------------------------------------------------------

$OPENSSL_CIPHERS = [];
if (function_exists('openssl_decrypt')) {
    $OPENSSL_CIPHERS = [
        'camellia-128' => [
            'key_size'   => 16,
            'block_size' => 16,
            'modes'      => [
                'ecb' => 'camellia-128-ecb',
                'cbc' => 'camellia-128-cbc',
                'cfb' => 'camellia-128-cfb',
                'ofb' => 'camellia-128-ofb',
            ],
        ],
        'camellia-192' => [
            'key_size'   => 24,
            'block_size' => 16,
            'modes'      => [
                'ecb' => 'camellia-192-ecb',
                'cbc' => 'camellia-192-cbc',
                'cfb' => 'camellia-192-cfb',
                'ofb' => 'camellia-192-ofb',
            ],
        ],
        'camellia-256' => [
            'key_size'   => 32,
            'block_size' => 16,
            'modes'      => [
                'ecb' => 'camellia-256-ecb',
                'cbc' => 'camellia-256-cbc',
                'cfb' => 'camellia-256-cfb',
                'ofb' => 'camellia-256-ofb',
            ],
        ],
        'seed' => [
            'key_size'   => 16,
            'block_size' => 16,
            'modes'      => [
                'ecb' => 'seed-ecb',
                'cbc' => 'seed-cbc',
                'cfb' => 'seed-cfb',
                'ofb' => 'seed-ofb',
            ],
        ],
        'desx' => [
            'key_size'   => 24,
            'block_size' => 8,
            'modes'      => [
                'cbc' => 'desx-cbc',
            ],
        ],
        'aes-128' => [
            'key_size'   => 16,
            'block_size' => 16,
            'modes'      => [
                'ctr' => 'aes-128-ctr',
            ],
        ],
        'aes-192' => [
            'key_size'   => 24,
            'block_size' => 16,
            'modes'      => [
                'ctr' => 'aes-192-ctr',
            ],
        ],
        'aes-256' => [
            'key_size'   => 32,
            'block_size' => 16,
            'modes'      => [
                'ctr' => 'aes-256-ctr',
            ],
        ],
    ];
}

// ---------------------------------------------------------------------------
// Key/IV fitting
// ---------------------------------------------------------------------------

function fit_key($key, $cipher_const, $mode_const) {
    $sizes = @mcrypt_module_get_supported_key_sizes($cipher_const);
    $key_len = strlen($key);

    if (empty($sizes)) {
        // Variable key size — use mcrypt_enc_get_key_size for max
        $td = @mcrypt_module_open($cipher_const, '', $mode_const, '');
        if ($td === false) return false;
        $max = mcrypt_enc_get_key_size($td);
        mcrypt_module_close($td);
        if ($key_len > $max) {
            return substr($key, 0, $max);
        }
        // For variable-size ciphers with no fixed sizes, use key as-is if > 0
        if ($key_len === 0) return str_repeat("\0", 1);
        return $key;
    }

    // Find closest valid key size
    sort($sizes);
    $best = $sizes[count($sizes) - 1]; // default to largest
    foreach ($sizes as $s) {
        if ($key_len <= $s) {
            $best = $s;
            break;
        }
    }

    if ($key_len < $best) {
        return $key . str_repeat("\0", $best - $key_len);
    } elseif ($key_len > $best) {
        return substr($key, 0, $best);
    }
    return $key;
}

function fit_iv($iv, $cipher_const, $mode_const) {
    $td = @mcrypt_module_open($cipher_const, '', $mode_const, '');
    if ($td === false) return false;
    $iv_size = mcrypt_enc_get_iv_size($td);
    mcrypt_module_close($td);

    if ($iv_size === 0) return '';

    $iv_len = strlen($iv);
    if ($iv_len < $iv_size) {
        return $iv . str_repeat("\0", $iv_size - $iv_len);
    } elseif ($iv_len > $iv_size) {
        return substr($iv, 0, $iv_size);
    }
    return $iv;
}

function get_iv_size($cipher_const, $mode_const) {
    $td = @mcrypt_module_open($cipher_const, '', $mode_const, '');
    if ($td === false) return 0;
    $size = mcrypt_enc_get_iv_size($td);
    mcrypt_module_close($td);
    return $size;
}

// ---------------------------------------------------------------------------
// OpenSSL key/IV fitting & decryption
// ---------------------------------------------------------------------------

function fit_key_openssl($key, $cipher_def) {
    $target = $cipher_def['key_size'];
    $len = strlen($key);
    if ($len < $target) {
        return $key . str_repeat("\0", $target - $len);
    } elseif ($len > $target) {
        return substr($key, 0, $target);
    }
    return $key;
}

function get_iv_size_openssl($method) {
    return openssl_cipher_iv_length($method);
}

function fit_iv_openssl($iv, $method) {
    $iv_size = openssl_cipher_iv_length($method);
    if ($iv_size === false || $iv_size === 0) return '';

    $iv_len = strlen($iv);
    if ($iv_len < $iv_size) {
        return $iv . str_repeat("\0", $iv_size - $iv_len);
    } elseif ($iv_len > $iv_size) {
        return substr($iv, 0, $iv_size);
    }
    return $iv;
}

function openssl_try_decrypt($ciphertext, $method, $key, $iv) {
    $result = @openssl_decrypt($ciphertext, $method, $key,
        OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
    // Drain error queue to prevent memory buildup
    while (openssl_error_string() !== false) {}
    return $result;
}

// ---------------------------------------------------------------------------
// --list-ciphers / --list-modes
// ---------------------------------------------------------------------------

function list_ciphers() {
    global $ALL_CIPHERS, $BLOCK_CIPHERS, $STREAM_CIPHERS, $OPENSSL_CIPHERS;
    echo "Supported ciphers:\n\n";
    echo str_pad("Name", 18) . str_pad("Engine", 10) . str_pad("Type", 10) . str_pad("Key sizes", 25) . "Block size\n";
    echo str_repeat("-", 80) . "\n";

    // mcrypt ciphers
    foreach ($ALL_CIPHERS as $name => $const) {
        $type = isset($BLOCK_CIPHERS[$name]) ? 'block' : 'stream';
        $sizes = @mcrypt_module_get_supported_key_sizes($const);
        if (empty($sizes)) {
            $td = @mcrypt_module_open($const, '', 'ecb', '');
            if ($td !== false) {
                $max = mcrypt_enc_get_key_size($td);
                $key_info = "1-$max (variable)";
                mcrypt_module_close($td);
            } else {
                $key_info = 'N/A';
            }
        } else {
            $key_info = implode(', ', $sizes);
        }

        $block = @mcrypt_get_block_size($const, 'ecb');
        $block_info = $block ? "{$block}B" : 'N/A';

        echo str_pad($name, 18) . str_pad('mcrypt', 10) . str_pad($type, 10) . str_pad($key_info, 25) . $block_info . "\n";
    }

    // OpenSSL ciphers
    foreach ($OPENSSL_CIPHERS as $name => $def) {
        $key_info = $def['key_size'];
        $block_info = "{$def['block_size']}B";
        $modes = implode(', ', array_keys($def['modes']));
        echo str_pad($name, 18) . str_pad('openssl', 10) . str_pad('block', 10) . str_pad($key_info, 25) . $block_info . "  [$modes]\n";
    }
}

function list_modes() {
    global $ALL_MODES;
    echo "Supported modes:\n\n";
    foreach ($ALL_MODES as $name => $const) {
        echo "  $name\n";
    }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parse_args($argv) {
    $opts = [
        'ct'          => null,
        'wl'          => null,
        'ivs'         => null,
        'encoding'    => 'auto',
        'ciphers'     => 'all',
        'modes'       => 'all',
        'threshold'   => 0.70,
        'top'         => 50,
        'key_format'  => 'raw',
        'iv_format'   => 'hex',
        'list_ciphers' => false,
        'list_modes'   => false,
        'reverse'      => false,
        'caesar'       => false,
        'char_shift'   => false,
        'reverse_key'  => false,
    ];

    $i = 1;
    while ($i < count($argv)) {
        $arg = $argv[$i];
        switch ($arg) {
            case '--ct':
                $opts['ct'] = $argv[++$i];
                break;
            case '--wl':
                $opts['wl'] = $argv[++$i];
                break;
            case '--ivs':
                $opts['ivs'] = $argv[++$i];
                break;
            case '--encoding':
                $opts['encoding'] = $argv[++$i];
                break;
            case '--ciphers':
                $opts['ciphers'] = $argv[++$i];
                break;
            case '--modes':
                $opts['modes'] = $argv[++$i];
                break;
            case '--threshold':
                $opts['threshold'] = floatval($argv[++$i]);
                break;
            case '--top':
                $opts['top'] = intval($argv[++$i]);
                break;
            case '--key-format':
                $opts['key_format'] = $argv[++$i];
                break;
            case '--iv-format':
                $opts['iv_format'] = $argv[++$i];
                break;
            case '--list-ciphers':
                $opts['list_ciphers'] = true;
                break;
            case '--list-modes':
                $opts['list_modes'] = true;
                break;
            case '--reverse':
                $opts['reverse'] = true;
                break;
            case '--caesar':
                $opts['caesar'] = true;
                break;
            case '--char-shift':
                $opts['char_shift'] = true;
                break;
            case '--reverse-key':
                $opts['reverse_key'] = true;
                break;
            default:
                echo "[ERROR] Unknown argument: $arg\n";
                exit(1);
        }
        $i++;
    }
    return $opts;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

$opts = parse_args($argv);

// Handle --list-* commands
if ($opts['list_ciphers']) {
    list_ciphers();
    exit(0);
}
if ($opts['list_modes']) {
    list_modes();
    exit(0);
}

// Validate required args
if (!$opts['ct'] || !$opts['wl']) {
    echo "Usage: php mcrypt_brute.php --ct <file> --wl <file> [options]\n";
    echo "       php mcrypt_brute.php --list-ciphers\n";
    echo "       php mcrypt_brute.php --list-modes\n";
    echo "\nOptions:\n";
    echo "  --ct <file>              Ciphertext file (required)\n";
    echo "  --wl <file>              Wordlist file (required)\n";
    echo "  --ivs <file>             IV list file (optional)\n";
    echo "  --encoding <hex|base64|auto>  Ciphertext encoding (default: auto)\n";
    echo "  --ciphers <list|all>     Comma-separated cipher names (default: all)\n";
    echo "  --modes <list|all>       Comma-separated mode names (default: all)\n";
    echo "  --threshold <float>      Min ASCII score 0.0-1.0 (default: 0.70)\n";
    echo "  --top <int>              Top N results to keep (default: 50)\n";
    echo "  --key-format <raw|hex|base64> Wordlist key format (default: raw)\n";
    echo "  --iv-format <raw|hex>    IV list format (default: hex)\n";
    echo "  --list-ciphers           List supported ciphers and exit\n";
    echo "  --list-modes             List supported modes and exit\n";
    exit(1);
}

// ---------------------------------------------------------------------------
// Load ciphertext
// ---------------------------------------------------------------------------

if (!file_exists($opts['ct'])) {
    echo "[ERROR] Ciphertext file not found: {$opts['ct']}\n";
    exit(1);
}

$ct_raw = file_get_contents($opts['ct']);
$ct_trimmed = trim($ct_raw);

// Detect or use specified encoding
$enc_used = $opts['encoding'];
if ($enc_used === 'auto') {
    $enc_used = detect_encoding($ct_trimmed);
    info("Auto-detected encoding: $enc_used");
}

// Generate ciphertext variants (original + reverse + caesar rotations)
$ct_variants = generate_ct_variants($ct_trimmed, $enc_used, $opts['reverse'], $opts['caesar'], $opts['char_shift']);
$variant_count = count($ct_variants);

if ($variant_count === 0) {
    echo "[ERROR] Failed to decode ciphertext with encoding: $enc_used\n";
    exit(1);
}

$ct_len = strlen($ct_variants[0][1]);
info("Loaded ciphertext: $ct_len bytes ($enc_used)");
if ($variant_count > 1) {
    $variant_names = array_map(function($v) { return $v[0]; }, $ct_variants);
    info("Generated $variant_count ciphertext variants: " . implode(', ', array_slice($variant_names, 0, 8)) . ($variant_count > 8 ? '...' : ''));
}

// ---------------------------------------------------------------------------
// Load wordlist (stream for memory efficiency — count lines first)
// ---------------------------------------------------------------------------

if (!file_exists($opts['wl'])) {
    echo "[ERROR] Wordlist file not found: {$opts['wl']}\n";
    exit(1);
}

$key_count = 0;
$fh = fopen($opts['wl'], 'r');
while (fgets($fh) !== false) $key_count++;
fclose($fh);
$key_multiplier = $opts['reverse_key'] ? 2 : 1;
info("Wordlist: $key_count keys (format: {$opts['key_format']})" . ($opts['reverse_key'] ? " + reversed = " . ($key_count * 2) . " effective keys" : ""));

// ---------------------------------------------------------------------------
// Load IVs
// ---------------------------------------------------------------------------

$ivs = [];
if ($opts['ivs'] && file_exists($opts['ivs'])) {
    $iv_lines = file($opts['ivs'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($iv_lines as $line) {
        $line = trim($line);
        if ($line === '') continue;
        if ($opts['iv_format'] === 'hex') {
            $decoded = hex_to_bytes($line);
            if ($decoded !== false) $ivs[] = $decoded;
        } else {
            $ivs[] = $line;
        }
    }
    info("Loaded " . count($ivs) . " IVs from file");
} else {
    // Single all-zeros IV (will be fitted per cipher)
    $ivs[] = str_repeat("\0", 32); // oversized, will be truncated to fit
    info("Using all-zeros IV (default)");
}

// ---------------------------------------------------------------------------
// Resolve cipher & mode lists
// ---------------------------------------------------------------------------

// Resolve cipher lists (mcrypt + openssl)
$mcrypt_cipher_list = [];
$openssl_cipher_list = [];

if ($opts['ciphers'] === 'all') {
    $mcrypt_cipher_list = $ALL_CIPHERS;
    $openssl_cipher_list = $OPENSSL_CIPHERS;
} else {
    foreach (explode(',', $opts['ciphers']) as $name) {
        $name = trim($name);
        if (isset($ALL_CIPHERS[$name])) {
            $mcrypt_cipher_list[$name] = $ALL_CIPHERS[$name];
        } elseif (isset($OPENSSL_CIPHERS[$name])) {
            $openssl_cipher_list[$name] = $OPENSSL_CIPHERS[$name];
        } else {
            echo "[WARN] Unknown cipher '$name' — skipping\n";
        }
    }
}

if ($opts['modes'] === 'all') {
    $mode_list = $ALL_MODES;
} else {
    $mode_list = [];
    foreach (explode(',', $opts['modes']) as $name) {
        $name = trim($name);
        if (isset($ALL_MODES[$name])) {
            $mode_list[$name] = $ALL_MODES[$name];
        } else {
            echo "[WARN] Unknown mode '$name' — skipping\n";
        }
    }
}

// Build unified cipher+mode combos with engine tag
$combos = [];

// mcrypt combos
foreach ($mcrypt_cipher_list as $c_name => $c_const) {
    $is_stream = isset($STREAM_CIPHERS[$c_name]);
    foreach ($mode_list as $m_name => $m_const) {
        if ($is_stream && $m_name !== 'stream') continue;
        if (!$is_stream && $m_name === 'stream') continue;

        $td = @mcrypt_module_open($c_const, '', $m_const, '');
        if ($td === false) continue;
        mcrypt_module_close($td);

        $combos[] = [
            'engine'  => 'mcrypt',
            'cipher'  => $c_name,
            'c_const' => $c_const,
            'mode'    => $m_name,
            'm_const' => $m_const,
        ];
    }
}

// OpenSSL combos
foreach ($openssl_cipher_list as $c_name => $c_def) {
    foreach ($mode_list as $m_name => $m_const) {
        // Only generate combos for modes this cipher supports
        if (!isset($c_def['modes'][$m_name])) continue;

        $method = $c_def['modes'][$m_name];

        $combos[] = [
            'engine'     => 'openssl',
            'cipher'     => $c_name,
            'mode'       => $m_name,
            'method'     => $method,
            'cipher_def' => $c_def,
        ];
    }
}

// Block-alignment pre-check: prune OpenSSL ECB/CBC combos where ciphertext
// length isn't a multiple of block size (would always return false)
$ct_check_len = strlen($ct_variants[0][1]);
$pruned = 0;
$combos = array_values(array_filter($combos, function($combo) use ($ct_check_len, &$pruned) {
    if ($combo['engine'] === 'openssl') {
        $m = $combo['mode'];
        if ($m === 'ecb' || $m === 'cbc') {
            $bs = $combo['cipher_def']['block_size'];
            if ($ct_check_len % $bs !== 0) {
                $pruned++;
                return false;
            }
        }
    }
    return true;
}));
if ($pruned > 0) {
    info("Pruned $pruned OpenSSL ECB/CBC combos (ciphertext not block-aligned)");
}

$combo_count = count($combos);
$iv_count = count($ivs);
$effective_keys = $key_count * $key_multiplier;
$total = $variant_count * $combo_count * $effective_keys * $iv_count;

$mcrypt_combos = count(array_filter($combos, function($c) { return $c['engine'] === 'mcrypt'; }));
$openssl_combos = $combo_count - $mcrypt_combos;
info("Testing $variant_count variants x $combo_count cipher+mode combos ($mcrypt_combos mcrypt + $openssl_combos openssl) x $effective_keys keys x $iv_count IVs = " . number_format($total) . " combos");

// ---------------------------------------------------------------------------
// Brute force loop
// ---------------------------------------------------------------------------

$threshold = $opts['threshold'];
$top_n = $opts['top'];
$results = [];
$tested = 0;
$start_time = microtime(true);
$last_progress = 0;

foreach ($ct_variants as $variant) {
    list($v_label, $ciphertext) = $variant;

    if ($variant_count > 1) {
        info("Testing variant: $v_label (" . strlen($ciphertext) . " bytes)");
    }

    foreach ($combos as $combo) {
        $c_name = $combo['cipher'];
        $m_name = $combo['mode'];
        $engine = $combo['engine'];

        // Open wordlist fresh for each cipher+mode combo
        $fh = fopen($opts['wl'], 'r');
        if (!$fh) continue;

        while (($line = fgets($fh)) !== false) {
            $line = rtrim($line, "\r\n");
            if ($line === '') continue;

            // Decode key
            if ($opts['key_format'] === 'hex') {
                $raw_key = hex_to_bytes($line);
                if ($raw_key === false) {
                    $tested += $iv_count * $key_multiplier;
                    continue;
                }
            } elseif ($opts['key_format'] === 'base64') {
                $raw_key = base64_decode(trim($line), true);
                if ($raw_key === false) {
                    $tested += $iv_count * $key_multiplier;
                    continue;
                }
            } else {
                $raw_key = $line;
            }

            // Build key candidates: original + optionally reversed
            $key_candidates = [[$raw_key, false]];
            if ($opts['reverse_key']) {
                $rev_key = strrev($raw_key);
                if ($rev_key !== $raw_key) {
                    $key_candidates[] = [$rev_key, true];
                }
            }

            foreach ($key_candidates as $kc) {
                list($candidate_key, $is_reversed) = $kc;

                // Fit key per engine
                if ($engine === 'mcrypt') {
                    $fitted_key = fit_key($candidate_key, $combo['c_const'], $combo['m_const']);
                } else {
                    $fitted_key = fit_key_openssl($candidate_key, $combo['cipher_def']);
                }
                if ($fitted_key === false) {
                    $tested += $iv_count;
                    continue;
                }

                foreach ($ivs as $raw_iv) {
                    $tested++;

                    if ($engine === 'mcrypt') {
                        // ── mcrypt decryption path ──
                        $c_const = $combo['c_const'];
                        $m_const = $combo['m_const'];

                        $fitted_iv = fit_iv($raw_iv, $c_const, $m_const);
                        if ($fitted_iv === false) continue;

                        $td = @mcrypt_module_open($c_const, '', $m_const, '');
                        if ($td === false) continue;

                        $init = @mcrypt_generic_init($td, $fitted_key, $fitted_iv);
                        if ($init === false || $init < 0) {
                            mcrypt_module_close($td);
                            continue;
                        }

                        $plaintext = @mdecrypt_generic($td, $ciphertext);
                        mcrypt_generic_deinit($td);
                        mcrypt_module_close($td);
                    } else {
                        // ── OpenSSL decryption path ──
                        $method = $combo['method'];

                        $fitted_iv = fit_iv_openssl($raw_iv, $method);

                        $plaintext = openssl_try_decrypt($ciphertext, $method, $fitted_key, $fitted_iv);
                    }

                    if ($plaintext === false || strlen($plaintext) === 0) continue;

                    $score = score_printable($plaintext);

                    if ($score >= $threshold) {
                        $key_hex = bytes_to_hex($fitted_key);
                        $iv_hex = bytes_to_hex($fitted_iv);
                        $preview = safe_preview($plaintext);
                        $key_ascii = safe_preview($candidate_key, 40);
                        $key_note = $is_reversed ? ' (rev)' : '';

                        $hit = [
                            'score'     => round($score * 100, 2),
                            'cipher'    => $c_name,
                            'mode'      => $m_name,
                            'variant'   => $v_label,
                            'key_ascii' => $key_ascii . $key_note,
                            'key_hex'   => $key_hex,
                            'iv_hex'    => $iv_hex,
                            'preview'   => $preview,
                        ];

                        echo sprintf("[HIT] score=%.2f cipher=%s mode=%s variant=%s key_hex=%s iv_hex=%s preview=\"%s\"\n",
                            $hit['score'], $c_name, $m_name, $v_label, $key_hex, $iv_hex, $preview);
                        flush();

                        $results[] = $hit;

                        // Keep only top N
                        usort($results, function($a, $b) {
                            return $b['score'] <=> $a['score'];
                        });
                        if (count($results) > $top_n) {
                            $results = array_slice($results, 0, $top_n);
                        }
                    }

                    // Emit progress periodically
                    if ($total > 0) {
                        $pct = $tested / $total;
                        if ($pct - $last_progress >= 0.001 || $tested === $total) {
                            emit_progress($pct);
                            $last_progress = $pct;
                        }
                    }
                }
            }
        }

        fclose($fh);
    }
}

$elapsed = round(microtime(true) - $start_time, 2);

// ---------------------------------------------------------------------------
// Final output
// ---------------------------------------------------------------------------

$hit_count = count($results);
echo "[DONE] $hit_count results above threshold (" . ($threshold * 100) . "%)\n";

// Sort final results
usort($results, function($a, $b) {
    return $b['score'] <=> $a['score'];
});

$json = json_encode([
    'results'      => $results,
    'total_tested' => $tested,
    'elapsed'      => $elapsed,
], JSON_PRETTY_PRINT);

echo "[RESULTS_JSON]\n$json\n";
flush();

info("Completed in {$elapsed}s — tested " . number_format($tested) . " combinations");
