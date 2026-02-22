<?php
/**
 * XXTEA CLI Tool — encrypt/decrypt using Ma Bingyao's xxtea.php
 *
 * Usage:
 *   php xxtea_tool.php encrypt <plaintext> <key> [--out <file>] [--format hex|base64|raw]
 *   php xxtea_tool.php decrypt <ciphertext> <key> [--format hex|base64|raw]
 *   php xxtea_tool.php decrypt-file <file> <key> [--encoding hex|base64|raw]
 *   php xxtea_tool.php test
 */

require_once __DIR__ . '/xxtea.php';

function usage() {
    echo "XXTEA CLI Tool (Ma Bingyao's xxtea.php)\n\n";
    echo "Usage:\n";
    echo "  php xxtea_tool.php encrypt <plaintext> <key> [--out <file>] [--format hex|base64|raw]\n";
    echo "  php xxtea_tool.php decrypt <ciphertext> <key> [--format hex|base64|raw]\n";
    echo "  php xxtea_tool.php decrypt-file <file> <key> [--encoding hex|base64|raw]\n";
    echo "  php xxtea_tool.php test\n\n";
    echo "Options:\n";
    echo "  --format   Output format for encrypt, input format for decrypt (default: base64)\n";
    echo "  --encoding Input encoding for decrypt-file (default: base64)\n";
    echo "  --out      Write raw ciphertext bytes to file (for brute-force testing)\n";
    exit(1);
}

function run_test() {
    echo "=== XXTEA Library Test ===\n\n";

    // Test vector from xxtea-php test suite
    $key = "1234567890";
    $plaintext = "Hello World! 你好，中国🇨🇳！";
    $expected_b64 = "D4t0rVXUDl3bnWdERhqJmFIanfn/6zAxAY9jD6n9MSMQNoD8TOS4rHHcGuE=";

    echo "Key:                $key\n";
    echo "Plaintext:          $plaintext\n";
    echo "Expected (base64):  $expected_b64\n\n";

    // Encrypt
    $encrypted = xxtea_encrypt($plaintext, $key);
    $got_b64 = base64_encode($encrypted);
    echo "Encrypted (base64): $got_b64\n";

    if ($got_b64 === $expected_b64) {
        echo "  -> ENCRYPT PASS\n\n";
    } else {
        echo "  -> ENCRYPT FAIL\n\n";
    }

    // Decrypt from expected
    $ct_bytes = base64_decode($expected_b64);
    $decrypted = xxtea_decrypt($ct_bytes, $key);
    echo "Decrypted:          $decrypted\n";

    if ($decrypted === $plaintext) {
        echo "  -> DECRYPT PASS\n\n";
    } else {
        echo "  -> DECRYPT FAIL\n\n";
    }

    // Round-trip
    $rt = xxtea_decrypt($encrypted, $key);
    echo "Round-trip:         $rt\n";
    if ($rt === $plaintext) {
        echo "  -> ROUND-TRIP PASS\n\n";
    } else {
        echo "  -> ROUND-TRIP FAIL\n\n";
    }

    // Additional simple ASCII test
    echo "--- Additional ASCII test ---\n";
    $key2 = "mysecretkey";
    $pt2 = "The quick brown fox jumps over the lazy dog";
    echo "Key:       $key2\n";
    echo "Plaintext: $pt2\n";

    $enc2 = xxtea_encrypt($pt2, $key2);
    $b64_2 = base64_encode($enc2);
    echo "Encrypted: $b64_2\n";
    echo "Hex:       " . bin2hex($enc2) . "\n";
    echo "Raw bytes: " . strlen($enc2) . " bytes\n";

    $dec2 = xxtea_decrypt($enc2, $key2);
    echo "Decrypted: $dec2\n";

    if ($dec2 === $pt2) {
        echo "  -> PASS\n";
    } else {
        echo "  -> FAIL\n";
    }
}

// --- Arg parsing ---

if ($argc < 2) usage();

$command = $argv[1];

if ($command === 'test') {
    run_test();
    exit(0);
}

if ($command === 'encrypt') {
    if ($argc < 4) usage();
    $plaintext = $argv[2];
    $key = $argv[3];
    $format = 'base64';
    $outfile = null;

    for ($i = 4; $i < $argc; $i++) {
        if ($argv[$i] === '--format' && isset($argv[$i+1])) {
            $format = $argv[++$i];
        } elseif ($argv[$i] === '--out' && isset($argv[$i+1])) {
            $outfile = $argv[++$i];
        }
    }

    $encrypted = xxtea_encrypt($plaintext, $key);

    if ($outfile) {
        file_put_contents($outfile, $encrypted);
        echo "Raw ciphertext written to: $outfile (" . strlen($encrypted) . " bytes)\n";
    }

    switch ($format) {
        case 'hex':
            echo bin2hex($encrypted) . "\n";
            break;
        case 'raw':
            echo $encrypted;
            break;
        case 'base64':
        default:
            echo base64_encode($encrypted) . "\n";
            break;
    }
    exit(0);
}

if ($command === 'decrypt') {
    if ($argc < 4) usage();
    $input = $argv[2];
    $key = $argv[3];
    $format = 'base64';

    for ($i = 4; $i < $argc; $i++) {
        if ($argv[$i] === '--format' && isset($argv[$i+1])) {
            $format = $argv[++$i];
        }
    }

    switch ($format) {
        case 'hex':
            $ciphertext = hex2bin($input);
            break;
        case 'raw':
            $ciphertext = $input;
            break;
        case 'base64':
        default:
            $ciphertext = base64_decode($input);
            break;
    }

    $decrypted = xxtea_decrypt($ciphertext, $key);
    if ($decrypted === false) {
        echo "[ERROR] Decryption failed (invalid data or key)\n";
        exit(1);
    }
    echo $decrypted . "\n";
    exit(0);
}

if ($command === 'decrypt-file') {
    if ($argc < 4) usage();
    $file = $argv[2];
    $key = $argv[3];
    $encoding = 'base64';

    for ($i = 4; $i < $argc; $i++) {
        if ($argv[$i] === '--encoding' && isset($argv[$i+1])) {
            $encoding = $argv[++$i];
        }
    }

    if (!file_exists($file)) {
        echo "[ERROR] File not found: $file\n";
        exit(1);
    }

    $raw = file_get_contents($file);

    switch ($encoding) {
        case 'hex':
            $ciphertext = hex2bin(trim($raw));
            break;
        case 'raw':
            $ciphertext = $raw;
            break;
        case 'base64':
        default:
            $ciphertext = base64_decode(trim($raw));
            break;
    }

    $decrypted = xxtea_decrypt($ciphertext, $key);
    if ($decrypted === false) {
        echo "[ERROR] Decryption failed (invalid data or key)\n";
        exit(1);
    }
    echo $decrypted . "\n";
    exit(0);
}

echo "[ERROR] Unknown command: $command\n";
usage();
