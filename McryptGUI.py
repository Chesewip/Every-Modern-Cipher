"""
mcrypt Cipher Brute-Force — GUI Wrapper
Wraps the mcrypt_brute.php CLI tool with a modern dark-themed interface.
"""

import customtkinter as ctk
import subprocess
import threading
import os
import sys
import re
import json
import time
from tkinter import filedialog

# ---------------------------------------------------------------------------
# Paths & Config
# ---------------------------------------------------------------------------

APP_TITLE = "Cipher Brute-Force (mcrypt + OpenSSL + PyCryptodome + Crypto++)"

# Color palette (Mantine-dark inspired — matches RC4 CipherCrackerGUI)
C = {
    "bg":        "#1a1b1e",
    "surface":   "#25262b",
    "surface2":  "#2c2e33",
    "border":    "#373a40",
    "text":      "#c1c2c5",
    "dimmed":    "#909296",
    "bright":    "#e9ecef",
    "accent":    "#339af0",
    "accent_h":  "#228be6",
    "green":     "#40c057",
    "green_d":   "#2b8a3e",
    "green_dd":  "#237032",
    "red":       "#fa5252",
    "red_d":     "#c92a2a",
    "orange":    "#ffa94d",
    "yellow":    "#ffd43b",
    "purple":    "#be4bdb",
    "purple_d":  "#9c36b5",
    "purple_dd": "#7b2d8e",
    "log_bg":    "#141517",
}

# mcrypt cipher names
BLOCK_CIPHERS = [
    "blowfish", "twofish", "des", "3des",
    "saferplus", "loki97", "gost", "rc2",
    "rijndael-128", "rijndael-192", "rijndael-256", "serpent",
    "cast-128", "cast-256", "xtea", "blowfish-compat",
]
STREAM_CIPHERS = ["arcfour", "wake", "enigma"]
MCRYPT_CIPHERS = BLOCK_CIPHERS + STREAM_CIPHERS

# OpenSSL-only ciphers (+ AES for CTR mode — same as rijndael-128 but via OpenSSL)
OPENSSL_CIPHERS = ["camellia-128", "camellia-192", "camellia-256", "seed", "desx", "aes-128", "aes-192", "aes-256"]

# PyCryptodome ciphers (unique stream ciphers not available in mcrypt/OpenSSL)
PYCRYPTO_CIPHERS = ["salsa20", "chacha20"]

# Crypto++ ciphers (block + stream not available in mcrypt/OpenSSL/PyCryptodome)
CRYPTOPP_BLOCK_CIPHERS = [
    "idea", "rc5", "rc6", "mars",
    "skipjack", "3way", "safer-sk64", "safer-sk128",
    "aria", "sm4", "lea", "hight", "tea", "square", "shark", "shacal2",
    "simon-64", "simon-128", "speck-64", "speck-128",
    "simeck-32", "simeck-64", "cham-64", "cham-128",
    "kalyna-128", "kalyna-256", "kalyna-512",
    "threefish-256", "threefish-512", "threefish-1024",
]
CRYPTOPP_STREAM_CIPHERS = [
    "sosemanuk", "rabbit", "hc-128", "hc-256", "panama", "seal", "xsalsa20",
]

# Gladman AES Round 1 candidates (128-bit block, routed via cryptopp_brute.exe)
GLADMAN_BLOCK_CIPHERS = [
    "crypton", "dfc", "e2", "frog", "magenta", "hpc",
]

# Botan 2.x ciphers (routed via cryptopp_brute.exe)
BOTAN_BLOCK_CIPHERS = [
    "misty1", "kasumi", "noekeon",
]

# Standalone block ciphers (routed via cryptopp_brute.exe)
STANDALONE_BLOCK_CIPHERS = [
    "clefia", "anubis", "khazad", "kuznyechik",
]

CRYPTOPP_CIPHERS = CRYPTOPP_BLOCK_CIPHERS + CRYPTOPP_STREAM_CIPHERS + GLADMAN_BLOCK_CIPHERS + BOTAN_BLOCK_CIPHERS + STANDALONE_BLOCK_CIPHERS

# XXTEA (standalone library, routed via PHP backend)
XXTEA_CIPHERS = ["xxtea"]

ALL_CIPHERS = MCRYPT_CIPHERS + OPENSSL_CIPHERS + PYCRYPTO_CIPHERS + CRYPTOPP_CIPHERS + XXTEA_CIPHERS
PHP_CIPHERS = MCRYPT_CIPHERS + OPENSSL_CIPHERS + XXTEA_CIPHERS  # handled by PHP backend

BLOCK_MODES = ["ecb", "cbc", "cfb", "ofb", "nofb", "ncfb", "ctr"]
STREAM_MODES = ["stream"]

# CFB feedback-size variants (Crypto++ only): cfb-8 through cfb-128 in 8-bit steps
CFB_MODES = [f"cfb-{n}" for n in range(8, 129, 8)]

ALL_MODES = BLOCK_MODES + STREAM_MODES


def get_app_dir():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


CONFIG_FILE = os.path.join(get_app_dir(), "mcrypt_config.json")


def find_php():
    """Locate php.exe relative to this script or in PATH."""
    base = get_app_dir()
    candidates = [
        os.path.join(base, "php", "php.exe"),
        os.path.join(base, "php.exe"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    # Try system PATH
    import shutil
    php = shutil.which("php") or shutil.which("php.exe")
    return php


def check_mcrypt(php_path):
    """Verify php has mcrypt loaded."""
    if not php_path:
        return False
    try:
        result = subprocess.run(
            [php_path, "-m"],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        return "mcrypt" in result.stdout.lower()
    except Exception:
        return False


def check_openssl(php_path):
    """Verify php has openssl loaded."""
    if not php_path:
        return False
    try:
        result = subprocess.run(
            [php_path, "-m"],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        return "openssl" in result.stdout.lower()
    except Exception:
        return False


def find_python():
    """Locate python executable."""
    import shutil
    return shutil.which("python") or shutil.which("python3") or sys.executable


def find_cryptopp():
    """Locate cryptopp_brute.exe relative to this script."""
    base = get_app_dir()
    exe = os.path.join(base, "cryptopp_brute.exe")
    if os.path.isfile(exe):
        return exe
    # Fallback: check build output directory
    exe2 = os.path.join(base, "build", "Release", "cryptopp_brute.exe")
    if os.path.isfile(exe2):
        return exe2
    return None


def check_pycryptodome(python_path):
    """Verify PyCryptodome is installed."""
    if not python_path:
        return False
    try:
        result = subprocess.run(
            [python_path, "-c", "from Crypto.Cipher import AES; print('ok')"],
            capture_output=True, text=True, timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        )
        return "ok" in result.stdout
    except Exception:
        return False


def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(cfg):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass


def format_elapsed(seconds):
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    if h > 0:
        return f"{h}:{m:02d}:{s:02d}"
    return f"{m}:{s:02d}"


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

class McryptBruteApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.php_path = find_php()
        self.has_mcrypt = check_mcrypt(self.php_path)
        self.has_openssl = check_openssl(self.php_path)
        self.python_path = find_python()
        self.has_pycryptodome = check_pycryptodome(self.python_path)
        self.cryptopp_path = find_cryptopp()
        self.has_cryptopp = self.cryptopp_path is not None
        self.process = None
        self.reader_thread = None
        self.stop_flag = threading.Event()
        self.start_time = None
        self.timer_id = None
        self._job_queue = []

        # Window setup
        self.title(APP_TITLE)
        self.geometry("1050x920")
        self.minsize(900, 780)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.configure(fg_color=C["bg"])

        cfg = load_config()

        # ── Title Bar ────────────────────────────────────────────────────
        title_frame = ctk.CTkFrame(self, fg_color=C["surface"], corner_radius=0, height=56)
        title_frame.pack(fill="x")
        title_frame.pack_propagate(False)

        title_inner = ctk.CTkFrame(title_frame, fg_color="transparent")
        title_inner.pack(fill="x", padx=24)

        ctk.CTkLabel(
            title_inner, text="Cipher Brute-Force",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color=C["bright"]
        ).pack(side="left", pady=14)

        php_text = self.php_path or "php.exe not found"
        php_color = C["dimmed"] if self.php_path else C["red"]
        ctk.CTkLabel(
            title_inner, text=php_text,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=php_color
        ).pack(side="right", pady=14)

        # ── Main Scrollable ──────────────────────────────────────────────
        main = ctk.CTkScrollableFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=20, pady=(12, 16))

        # ── Panel: Ciphertext ────────────────────────────────────────────
        self._section_label(main, "CIPHERTEXT")
        ct_panel = ctk.CTkFrame(main, fg_color=C["surface"], corner_radius=8)
        ct_panel.pack(fill="x", pady=(0, 12))
        ct_inner = ctk.CTkFrame(ct_panel, fg_color="transparent")
        ct_inner.pack(fill="x", padx=16, pady=14)

        # From file
        file_row = ctk.CTkFrame(ct_inner, fg_color="transparent")
        file_row.pack(fill="x", pady=(0, 6))

        ctk.CTkLabel(
            file_row, text="File",
            font=ctk.CTkFont(size=12), text_color=C["dimmed"]
        ).pack(side="left", padx=(0, 6))

        self.ct_var = ctk.StringVar(value=cfg.get("ct_path", ""))
        self.ct_entry = ctk.CTkEntry(
            file_row, textvariable=self.ct_var,
            placeholder_text="Select ciphertext file...",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["surface2"], border_color=C["border"],
            text_color=C["text"]
        )
        self.ct_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            file_row, text="Browse", width=80, height=30,
            fg_color=C["surface2"], hover_color=C["border"],
            text_color=C["text"], border_width=1, border_color=C["border"],
            command=self.browse_ciphertext
        ).pack(side="right")

        # Encoding selector
        enc_row = ctk.CTkFrame(ct_inner, fg_color="transparent")
        enc_row.pack(fill="x", pady=(6, 0))

        ctk.CTkLabel(
            enc_row, text="Encoding",
            font=ctk.CTkFont(size=12), text_color=C["dimmed"]
        ).pack(side="left", padx=(0, 6))

        self.encoding_var = ctk.StringVar(value=cfg.get("encoding", "auto"))
        for val in ["auto", "hex", "base64"]:
            ctk.CTkRadioButton(
                enc_row, text=val.capitalize(),
                variable=self.encoding_var, value=val,
                font=ctk.CTkFont(size=12), text_color=C["text"],
                fg_color=C["accent"], hover_color=C["accent_h"],
                border_color=C["border"]
            ).pack(side="left", padx=(0, 16))

        # ── Panel: Wordlist / Key ────────────────────────────────────────
        self._section_label(main, "WORDLIST / KEY")
        wl_panel = ctk.CTkFrame(main, fg_color=C["surface"], corner_radius=8)
        wl_panel.pack(fill="x", pady=(0, 12))
        wl_inner = ctk.CTkFrame(wl_panel, fg_color="transparent")
        wl_inner.pack(fill="x", padx=16, pady=14)

        self.wl_mode = ctk.StringVar(value=cfg.get("wl_mode", "file"))

        # Single key
        word_row = ctk.CTkFrame(wl_inner, fg_color="transparent")
        word_row.pack(fill="x", pady=(0, 6))

        ctk.CTkRadioButton(
            word_row, text="Single key",
            variable=self.wl_mode, value="word",
            font=ctk.CTkFont(size=13), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"],
            command=self._on_wl_mode_change
        ).pack(side="left")

        self.single_key_var = ctk.StringVar(value=cfg.get("single_key", ""))
        self.single_key_entry = ctk.CTkEntry(
            word_row, textvariable=self.single_key_var,
            placeholder_text="Type a key to test...",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["surface2"], border_color=C["border"],
            text_color=C["text"]
        )
        self.single_key_entry.pack(side="left", fill="x", expand=True, padx=(12, 0))

        # Wordlist file
        file_row2 = ctk.CTkFrame(wl_inner, fg_color="transparent")
        file_row2.pack(fill="x", pady=(6, 0))

        ctk.CTkRadioButton(
            file_row2, text="From file",
            variable=self.wl_mode, value="file",
            font=ctk.CTkFont(size=13), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"],
            command=self._on_wl_mode_change
        ).pack(side="left")

        self.wl_var = ctk.StringVar(value=cfg.get("wl_path", ""))
        self.wl_entry = ctk.CTkEntry(
            file_row2, textvariable=self.wl_var,
            placeholder_text="Select wordlist file...",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["surface2"], border_color=C["border"],
            text_color=C["text"]
        )
        self.wl_entry.pack(side="left", fill="x", expand=True, padx=(12, 8))

        self.wl_browse_btn = ctk.CTkButton(
            file_row2, text="Browse", width=80, height=30,
            fg_color=C["surface2"], hover_color=C["border"],
            text_color=C["text"], border_width=1, border_color=C["border"],
            command=self.browse_wordlist
        )
        self.wl_browse_btn.pack(side="right")

        # Key format toggle
        kf_row = ctk.CTkFrame(wl_inner, fg_color="transparent")
        kf_row.pack(fill="x", pady=(8, 0))

        ctk.CTkLabel(
            kf_row, text="Key format",
            font=ctk.CTkFont(size=12), text_color=C["dimmed"]
        ).pack(side="left", padx=(0, 6))

        self.key_format_var = ctk.StringVar(value=cfg.get("key_format", "raw"))
        for val, label in [("raw", "Raw text"), ("hex", "Hex"), ("base64", "Base64")]:
            ctk.CTkRadioButton(
                kf_row, text=label,
                variable=self.key_format_var, value=val,
                font=ctk.CTkFont(size=12), text_color=C["text"],
                fg_color=C["accent"], hover_color=C["accent_h"],
                border_color=C["border"]
            ).pack(side="left", padx=(0, 16))

        self._on_wl_mode_change()

        # ── Panel: IV Source ─────────────────────────────────────────────
        self._section_label(main, "IV SOURCE")
        iv_panel = ctk.CTkFrame(main, fg_color=C["surface"], corner_radius=8)
        iv_panel.pack(fill="x", pady=(0, 12))
        iv_inner = ctk.CTkFrame(iv_panel, fg_color="transparent")
        iv_inner.pack(fill="x", padx=16, pady=14)

        self.iv_mode = ctk.StringVar(value=cfg.get("iv_mode", "zeros"))

        # All zeros
        zeros_row = ctk.CTkFrame(iv_inner, fg_color="transparent")
        zeros_row.pack(fill="x", pady=(0, 4))
        ctk.CTkRadioButton(
            zeros_row, text="All-zeros (default)",
            variable=self.iv_mode, value="zeros",
            font=ctk.CTkFont(size=13), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"],
            command=self._on_iv_mode_change
        ).pack(side="left")

        # All ASCII '0' (0x30)
        ascii_zeros_row = ctk.CTkFrame(iv_inner, fg_color="transparent")
        ascii_zeros_row.pack(fill="x", pady=(0, 4))
        ctk.CTkRadioButton(
            ascii_zeros_row, text="All ASCII '0' (0x30)",
            variable=self.iv_mode, value="ascii_zeros",
            font=ctk.CTkFont(size=13), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"],
            command=self._on_iv_mode_change
        ).pack(side="left")

        # Single IV
        single_iv_row = ctk.CTkFrame(iv_inner, fg_color="transparent")
        single_iv_row.pack(fill="x", pady=(4, 4))
        ctk.CTkRadioButton(
            single_iv_row, text="Single IV (hex)",
            variable=self.iv_mode, value="single",
            font=ctk.CTkFont(size=13), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"],
            command=self._on_iv_mode_change
        ).pack(side="left")

        self.single_iv_var = ctk.StringVar(value=cfg.get("single_iv", ""))
        self.single_iv_entry = ctk.CTkEntry(
            single_iv_row, textvariable=self.single_iv_var,
            placeholder_text="e.g. 00000000000000000000000000000000",
            width=400,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["surface2"], border_color=C["border"],
            text_color=C["text"]
        )
        self.single_iv_entry.pack(side="left", padx=(12, 0))

        # IV list file
        iv_file_row = ctk.CTkFrame(iv_inner, fg_color="transparent")
        iv_file_row.pack(fill="x", pady=(4, 0))
        ctk.CTkRadioButton(
            iv_file_row, text="IV list file",
            variable=self.iv_mode, value="file",
            font=ctk.CTkFont(size=13), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"],
            command=self._on_iv_mode_change
        ).pack(side="left")

        self.iv_file_var = ctk.StringVar(value=cfg.get("iv_path", ""))
        self.iv_file_entry = ctk.CTkEntry(
            iv_file_row, textvariable=self.iv_file_var,
            placeholder_text="Select IV list file...",
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=C["surface2"], border_color=C["border"],
            text_color=C["text"]
        )
        self.iv_file_entry.pack(side="left", fill="x", expand=True, padx=(12, 8))

        self.iv_browse_btn = ctk.CTkButton(
            iv_file_row, text="Browse", width=80, height=30,
            fg_color=C["surface2"], hover_color=C["border"],
            text_color=C["text"], border_width=1, border_color=C["border"],
            command=self.browse_iv_file
        )
        self.iv_browse_btn.pack(side="right")

        self._on_iv_mode_change()

        # ── Panel: Cipher Selection ──────────────────────────────────────
        self._section_label(main, "CIPHER SELECTION")
        cipher_panel = ctk.CTkFrame(main, fg_color=C["surface"], corner_radius=8)
        cipher_panel.pack(fill="x", pady=(0, 12))
        cipher_inner = ctk.CTkFrame(cipher_panel, fg_color="transparent")
        cipher_inner.pack(fill="x", padx=16, pady=14)

        saved_ciphers = cfg.get("ciphers", ALL_CIPHERS)
        self.cipher_vars = {}
        COLS = 5

        # ── Global buttons row ──
        cipher_btns = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        cipher_btns.pack(fill="x", pady=(0, 8))

        ctk.CTkButton(
            cipher_btns, text="Select All", width=90, height=28,
            font=ctk.CTkFont(size=11),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#ffffff",
            command=self._select_all_ciphers
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            cipher_btns, text="Deselect All", width=100, height=28,
            font=ctk.CTkFont(size=11),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color=C["dimmed"], border_width=1, border_color=C["border"],
            command=self._deselect_all_ciphers
        ).pack(side="left")

        # ── mcrypt group ──
        mcrypt_header = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        mcrypt_header.pack(fill="x", pady=(4, 4))

        ctk.CTkLabel(
            mcrypt_header, text="mcrypt",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["accent"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            mcrypt_header, text="Select All Block", width=120, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color=C["text"], border_width=1, border_color=C["border"],
            command=self._select_all_block
        ).pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            mcrypt_header, text="Select All Stream", width=120, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color=C["text"], border_width=1, border_color=C["border"],
            command=self._select_all_stream
        ).pack(side="left", padx=(0, 4))

        mcrypt_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        mcrypt_grid.pack(fill="x", pady=(0, 8))

        for i, name in enumerate(MCRYPT_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                mcrypt_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["accent"], hover_color=C["accent_h"],
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # ── OpenSSL group ──
        ossl_header = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        ossl_header.pack(fill="x", pady=(4, 4))

        ctk.CTkLabel(
            ossl_header, text="OpenSSL",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["green"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            ossl_header, text="Select All OpenSSL", width=140, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["green_dd"], hover_color=C["green_d"],
            text_color="#ffffff",
            command=self._select_all_openssl
        ).pack(side="left", padx=(0, 4))

        ossl_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        ossl_grid.pack(fill="x", pady=(0, 8))

        for i, name in enumerate(OPENSSL_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                ossl_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["green"], hover_color=C["green_d"],
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # ── PyCryptodome group ──
        pyc_header = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        pyc_header.pack(fill="x", pady=(4, 4))

        ctk.CTkLabel(
            pyc_header, text="PyCryptodome",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["purple"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            pyc_header, text="Select All PyCryptodome", width=160, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["purple_dd"], hover_color=C["purple_d"],
            text_color="#ffffff",
            command=self._select_all_pycrypto
        ).pack(side="left", padx=(0, 4))

        pyc_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        pyc_grid.pack(fill="x", pady=(0, 8))

        for i, name in enumerate(PYCRYPTO_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                pyc_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["purple"], hover_color=C["purple_d"],
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # ── Crypto++ group ──
        cpp_header = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        cpp_header.pack(fill="x", pady=(4, 4))

        ctk.CTkLabel(
            cpp_header, text="Crypto++",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["orange"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            cpp_header, text="Select All Crypto++", width=150, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color="#ffffff",
            command=self._select_all_cryptopp
        ).pack(side="left", padx=(0, 4))

        # Block ciphers sub-label
        ctk.CTkLabel(
            cipher_inner, text="block ciphers",
            font=ctk.CTkFont(size=10),
            text_color=C["dimmed"]
        ).pack(anchor="w", pady=(2, 2))

        cpp_block_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        cpp_block_grid.pack(fill="x", pady=(0, 4))

        for i, name in enumerate(CRYPTOPP_BLOCK_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                cpp_block_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["orange"], hover_color="#e8940a",
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # Stream ciphers sub-label
        ctk.CTkLabel(
            cipher_inner, text="stream ciphers",
            font=ctk.CTkFont(size=10),
            text_color=C["dimmed"]
        ).pack(anchor="w", pady=(2, 2))

        cpp_stream_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        cpp_stream_grid.pack(fill="x")

        for i, name in enumerate(CRYPTOPP_STREAM_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                cpp_stream_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["orange"], hover_color="#e8940a",
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # AES Round 1 candidates sub-label
        gladman_header = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        gladman_header.pack(fill="x", pady=(6, 4))

        ctk.CTkLabel(
            gladman_header, text="AES Round 1 candidates",
            font=ctk.CTkFont(size=10),
            text_color=C["dimmed"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            gladman_header, text="Select All AES R1", width=140, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color="#ffffff",
            command=self._select_all_gladman
        ).pack(side="left", padx=(0, 4))

        gladman_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        gladman_grid.pack(fill="x")

        for i, name in enumerate(GLADMAN_BLOCK_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                gladman_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["orange"], hover_color="#e8940a",
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # Botan ciphers sub-label
        botan_header = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        botan_header.pack(fill="x", pady=(6, 4))

        ctk.CTkLabel(
            botan_header, text="Botan ciphers",
            font=ctk.CTkFont(size=10),
            text_color=C["dimmed"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            botan_header, text="Select All Botan", width=140, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color="#ffffff",
            command=self._select_all_botan
        ).pack(side="left", padx=(0, 4))

        botan_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        botan_grid.pack(fill="x")

        for i, name in enumerate(BOTAN_BLOCK_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                botan_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["orange"], hover_color="#e8940a",
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # Standalone ciphers sub-label
        standalone_header = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        standalone_header.pack(fill="x", pady=(6, 4))

        ctk.CTkLabel(
            standalone_header, text="Standalone ciphers",
            font=ctk.CTkFont(size=10),
            text_color=C["dimmed"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            standalone_header, text="Select All Standalone", width=160, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color="#ffffff",
            command=self._select_all_standalone
        ).pack(side="left", padx=(0, 4))

        standalone_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        standalone_grid.pack(fill="x")

        for i, name in enumerate(STANDALONE_BLOCK_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                standalone_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["orange"], hover_color="#e8940a",
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # ── XXTEA group ──
        xxtea_header = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        xxtea_header.pack(fill="x", pady=(8, 4))

        ctk.CTkLabel(
            xxtea_header, text="XXTEA",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["red"]
        ).pack(side="left", padx=(0, 10))

        xxtea_grid = ctk.CTkFrame(cipher_inner, fg_color="transparent")
        xxtea_grid.pack(fill="x")

        for i, name in enumerate(XXTEA_CIPHERS):
            var = ctk.BooleanVar(value=(name in saved_ciphers))
            self.cipher_vars[name] = var
            cb = ctk.CTkCheckBox(
                xxtea_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["red"], hover_color=C["red_d"],
                border_color=C["border"],
                width=160
            )
            cb.grid(row=i // COLS, column=i % COLS, sticky="w", padx=4, pady=2)

        # ── Panel: Mode Selection ────────────────────────────────────────
        self._section_label(main, "MODE SELECTION")
        mode_panel = ctk.CTkFrame(main, fg_color=C["surface"], corner_radius=8)
        mode_panel.pack(fill="x", pady=(0, 12))
        mode_inner = ctk.CTkFrame(mode_panel, fg_color="transparent")
        mode_inner.pack(fill="x", padx=16, pady=14)

        mode_btn_row = ctk.CTkFrame(mode_inner, fg_color="transparent")
        mode_btn_row.pack(fill="x", pady=(0, 6))

        ctk.CTkButton(
            mode_btn_row, text="Select All", width=90, height=26,
            font=ctk.CTkFont(size=11),
            fg_color=C["accent"], hover_color=C["accent_h"],
            text_color="#ffffff",
            command=self._select_all_modes
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            mode_btn_row, text="Deselect All", width=100, height=26,
            font=ctk.CTkFont(size=11),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color=C["dimmed"], border_width=1, border_color=C["border"],
            command=self._deselect_all_modes
        ).pack(side="left")

        saved_modes = cfg.get("modes", ALL_MODES)
        mode_checks_row = ctk.CTkFrame(mode_inner, fg_color="transparent")
        mode_checks_row.pack(fill="x", pady=(0, 6))

        self.mode_vars = {}
        for name in ALL_MODES:
            var = ctk.BooleanVar(value=(name in saved_modes))
            self.mode_vars[name] = var
            ctk.CTkCheckBox(
                mode_checks_row, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=C["text"],
                fg_color=C["accent"], hover_color=C["accent_h"],
                border_color=C["border"],
                width=90
            ).pack(side="left", padx=(0, 8))

        # ── CFB feedback-size variants (Crypto++ only) ──
        cfb_header = ctk.CTkFrame(mode_inner, fg_color="transparent")
        cfb_header.pack(fill="x", pady=(4, 4))

        ctk.CTkLabel(
            cfb_header, text="CFB feedback sizes (Crypto++ only)",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["orange"]
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            cfb_header, text="Select All CFB", width=110, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color="#ffffff",
            command=self._select_all_cfb_modes
        ).pack(side="left", padx=(0, 4))

        ctk.CTkButton(
            cfb_header, text="Deselect All CFB", width=120, height=24,
            font=ctk.CTkFont(size=10),
            fg_color=C["surface2"], hover_color=C["border"],
            text_color=C["dimmed"], border_width=1, border_color=C["border"],
            command=self._deselect_all_cfb_modes
        ).pack(side="left", padx=(0, 4))

        cfb_grid = ctk.CTkFrame(mode_inner, fg_color="transparent")
        cfb_grid.pack(fill="x")

        for i, name in enumerate(CFB_MODES):
            var = ctk.BooleanVar(value=(name in saved_modes))
            self.mode_vars[name] = var
            ctk.CTkCheckBox(
                cfb_grid, text=name, variable=var,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=C["text"],
                fg_color=C["orange"], hover_color="#e8940a",
                border_color=C["border"],
                width=90
            ).grid(row=i // 8, column=i % 8, sticky="w", padx=4, pady=2)

        # ── Panel: Options ───────────────────────────────────────────────
        self._section_label(main, "OPTIONS")
        opts_panel = ctk.CTkFrame(main, fg_color=C["surface"], corner_radius=8)
        opts_panel.pack(fill="x", pady=(0, 12))
        opts_inner = ctk.CTkFrame(opts_panel, fg_color="transparent")
        opts_inner.pack(fill="x", padx=16, pady=14)

        # CT variant options row
        variant_row = ctk.CTkFrame(opts_inner, fg_color="transparent")
        variant_row.pack(fill="x", pady=(0, 8))

        self.reverse_var = ctk.BooleanVar(value=cfg.get("reverse", False))
        ctk.CTkCheckBox(
            variant_row, text="Test reversed", variable=self.reverse_var,
            font=ctk.CTkFont(size=12), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"]
        ).pack(side="left", padx=(0, 16))

        self.caesar_var = ctk.BooleanVar(value=cfg.get("caesar", False))
        ctk.CTkCheckBox(
            variant_row, text="Test Caesar rotations", variable=self.caesar_var,
            font=ctk.CTkFont(size=12), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"]
        ).pack(side="left", padx=(0, 16))

        self.char_shift_var = ctk.BooleanVar(value=cfg.get("char_shift", False))
        ctk.CTkCheckBox(
            variant_row, text="Test char shifts", variable=self.char_shift_var,
            font=ctk.CTkFont(size=12), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"]
        ).pack(side="left", padx=(0, 16))

        self.reverse_key_var = ctk.BooleanVar(value=cfg.get("reverse_key", False))
        ctk.CTkCheckBox(
            variant_row, text="Test reversed keys", variable=self.reverse_key_var,
            font=ctk.CTkFont(size=12), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"]
        ).pack(side="left", padx=(0, 16))

        self.all_key_sizes_var = ctk.BooleanVar(value=cfg.get("all_key_sizes", False))
        ctk.CTkCheckBox(
            variant_row, text="Test all key sizes", variable=self.all_key_sizes_var,
            font=ctk.CTkFont(size=12), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"]
        ).pack(side="left", padx=(0, 16))

        self.repeat_key_var = ctk.BooleanVar(value=cfg.get("repeat_key", False))
        ctk.CTkCheckBox(
            variant_row, text="Test repeated key", variable=self.repeat_key_var,
            font=ctk.CTkFont(size=12), text_color=C["text"],
            fg_color=C["accent"], hover_color=C["accent_h"],
            border_color=C["border"]
        ).pack(side="left", padx=(0, 16))

        ctk.CTkLabel(
            variant_row,
            text="hex: 15 shifts (0-9a-f)  base64: 63 shifts (A-Za-z0-9+/)",
            font=ctk.CTkFont(size=11), text_color=C["dimmed"]
        ).pack(side="left")

        # Threshold / Top-N row
        opts_row = ctk.CTkFrame(opts_inner, fg_color="transparent")
        opts_row.pack(fill="x")

        ctk.CTkLabel(
            opts_row, text="Threshold",
            font=ctk.CTkFont(size=12), text_color=C["dimmed"]
        ).pack(side="left", padx=(0, 6))

        self.threshold_var = ctk.DoubleVar(value=cfg.get("threshold", 70.0))
        self.threshold_slider = ctk.CTkSlider(
            opts_row, from_=0, to=100, variable=self.threshold_var,
            width=200, height=16,
            fg_color=C["surface2"], progress_color=C["accent"],
            button_color=C["accent"], button_hover_color=C["accent_h"],
            command=self._on_threshold_change
        )
        self.threshold_slider.pack(side="left", padx=(0, 6))

        self.threshold_label = ctk.CTkLabel(
            opts_row, text=f"{self.threshold_var.get():.0f}%",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=C["text"], width=40
        )
        self.threshold_label.pack(side="left", padx=(0, 24))

        ctk.CTkLabel(
            opts_row, text="Top N",
            font=ctk.CTkFont(size=12), text_color=C["dimmed"]
        ).pack(side="left", padx=(0, 6))

        self.topn_var = ctk.StringVar(value=str(cfg.get("top_n", "50")))
        ctk.CTkComboBox(
            opts_row, values=["10", "25", "50", "100"],
            variable=self.topn_var, width=80, state="readonly",
            fg_color=C["surface2"], border_color=C["border"],
            button_color=C["border"], button_hover_color=C["dimmed"],
            dropdown_fg_color=C["surface2"],
            font=ctk.CTkFont(family="Consolas", size=12)
        ).pack(side="left")

        # ── Control Bar ──────────────────────────────────────────────────
        ctrl_frame = ctk.CTkFrame(main, fg_color="transparent")
        ctrl_frame.pack(fill="x", pady=(0, 8))

        self.start_btn = ctk.CTkButton(
            ctrl_frame, text="Start", width=160, height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color=C["green_d"], hover_color=C["green_dd"],
            text_color="#ffffff", command=self.start_cracking
        )
        self.start_btn.pack(side="left")

        self.stop_btn = ctk.CTkButton(
            ctrl_frame, text="Stop", width=80, height=40,
            font=ctk.CTkFont(size=13, weight="bold"),
            fg_color=C["red_d"], hover_color="#a52222",
            text_color="#ffffff", state="disabled",
            command=self.stop_cracking
        )
        self.stop_btn.pack(side="left", padx=(8, 0))

        self.timer_label = ctk.CTkLabel(
            ctrl_frame, text="",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=C["dimmed"]
        )
        self.timer_label.pack(side="right", padx=(8, 0))

        self.clear_btn = ctk.CTkButton(
            ctrl_frame, text="Clear", width=70, height=40,
            font=ctk.CTkFont(size=12),
            fg_color=C["surface"], hover_color=C["surface2"],
            text_color=C["dimmed"], border_width=1, border_color=C["border"],
            command=self.clear_all
        )
        self.clear_btn.pack(side="right")

        # ── Progress Bar ─────────────────────────────────────────────────
        self.progress = ctk.CTkProgressBar(
            main, height=3, corner_radius=0,
            fg_color=C["surface"], progress_color=C["accent"]
        )
        self.progress.pack(fill="x")
        self.progress.set(0)

        # ── Results Table ────────────────────────────────────────────────
        self._section_label(main, "RESULTS")

        results_frame = ctk.CTkFrame(main, fg_color=C["surface"], corner_radius=8)
        results_frame.pack(fill="x", pady=(0, 8))

        # Header
        header = ctk.CTkFrame(results_frame, fg_color=C["surface2"], corner_radius=0)
        header.pack(fill="x", padx=2, pady=(2, 0))

        col_widths = [60, 120, 60, 110, 120, 100, 200]
        col_names = ["Score", "Cipher", "Mode", "Variant", "Key (ASCII)", "IV (hex)", "Preview"]
        for w, name in zip(col_widths, col_names):
            ctk.CTkLabel(
                header, text=name, width=w,
                font=ctk.CTkFont(size=11, weight="bold"),
                text_color=C["dimmed"]
            ).pack(side="left", padx=4, pady=4)

        self.results_scroll = ctk.CTkScrollableFrame(
            results_frame, fg_color="transparent", height=160
        )
        self.results_scroll.pack(fill="x", padx=2, pady=(0, 2))
        self.result_rows = []

        # ── Output Log ───────────────────────────────────────────────────
        self._section_label(main, "OUTPUT LOG")

        self.log_text = ctk.CTkTextbox(
            main,
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word", state="disabled",
            fg_color=C["log_bg"], text_color=C["text"],
            corner_radius=8,
            border_width=1, border_color=C["border"],
            height=180
        )
        self.log_text.pack(fill="x", pady=(0, 4))

        # ── Status Bar ───────────────────────────────────────────────────
        status_frame = ctk.CTkFrame(main, fg_color="transparent", height=24)
        status_frame.pack(fill="x", pady=(6, 0))

        engines = []
        if self.has_mcrypt:
            engines.append("mcrypt")
        if self.has_openssl:
            engines.append("OpenSSL")
        if self.has_pycryptodome:
            engines.append("PyCryptodome")
        if self.has_cryptopp:
            engines.append("Crypto++")

        if engines:
            status_text = f"Ready ({' + '.join(engines)})"
            status_color = C["dimmed"]
        elif self.php_path:
            status_text = "php.exe found but mcrypt extension not loaded — check php.ini"
            status_color = C["orange"]
        else:
            status_text = "php.exe not found — place PHP 7.1.33 in the php/ folder"
            status_color = C["red"]

        self.status_label = ctk.CTkLabel(
            status_frame, text=status_text,
            font=ctk.CTkFont(size=11), text_color=status_color
        )
        self.status_label.pack(side="left")

        self._max_progress = 0.0
        self._progress_determinate = True

    # ── Helpers ────────────────────────────────────────────────────────────

    @staticmethod
    def _section_label(parent, text):
        ctk.CTkLabel(
            parent, text=text,
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color=C["dimmed"]
        ).pack(anchor="w", pady=(0, 4))

    # ── Cipher/Mode Selection ─────────────────────────────────────────────

    def _select_all_block(self):
        for name in BLOCK_CIPHERS + OPENSSL_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_stream(self):
        for name in STREAM_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_openssl(self):
        for name in OPENSSL_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_pycrypto(self):
        for name in PYCRYPTO_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_cryptopp(self):
        for name in CRYPTOPP_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_gladman(self):
        for name in GLADMAN_BLOCK_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_botan(self):
        for name in BOTAN_BLOCK_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_standalone(self):
        for name in STANDALONE_BLOCK_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_xxtea(self):
        for name in XXTEA_CIPHERS:
            if name in self.cipher_vars:
                self.cipher_vars[name].set(True)

    def _select_all_ciphers(self):
        for var in self.cipher_vars.values():
            var.set(True)

    def _deselect_all_ciphers(self):
        for var in self.cipher_vars.values():
            var.set(False)

    def _select_all_modes(self):
        for var in self.mode_vars.values():
            var.set(True)

    def _deselect_all_modes(self):
        for var in self.mode_vars.values():
            var.set(False)

    def _select_all_cfb_modes(self):
        for name in CFB_MODES:
            if name in self.mode_vars:
                self.mode_vars[name].set(True)

    def _deselect_all_cfb_modes(self):
        for name in CFB_MODES:
            if name in self.mode_vars:
                self.mode_vars[name].set(False)

    # ── Mode Toggles ──────────────────────────────────────────────────────

    def _on_wl_mode_change(self):
        if self.wl_mode.get() == "word":
            self.single_key_entry.configure(state="normal", text_color=C["text"])
            self.wl_entry.configure(state="disabled", text_color=C["border"])
            self.wl_browse_btn.configure(state="disabled")
        else:
            self.single_key_entry.configure(state="disabled", text_color=C["border"])
            self.wl_entry.configure(state="normal", text_color=C["text"])
            self.wl_browse_btn.configure(state="normal")

    def _on_iv_mode_change(self):
        mode = self.iv_mode.get()
        # Single IV entry
        if mode == "single":
            self.single_iv_entry.configure(state="normal", text_color=C["text"])
        else:
            self.single_iv_entry.configure(state="disabled", text_color=C["border"])
        # IV file
        if mode == "file":
            self.iv_file_entry.configure(state="normal", text_color=C["text"])
            self.iv_browse_btn.configure(state="normal")
        else:
            self.iv_file_entry.configure(state="disabled", text_color=C["border"])
            self.iv_browse_btn.configure(state="disabled")

    def _on_threshold_change(self, value):
        self.threshold_label.configure(text=f"{value:.0f}%")

    # ── File Browsers ─────────────────────────────────────────────────────

    def browse_ciphertext(self):
        init_dir = os.path.join(get_app_dir(), "cts")
        if self.ct_var.get():
            d = os.path.dirname(self.ct_var.get())
            if os.path.isdir(d):
                init_dir = d
        path = filedialog.askopenfilename(
            title="Select Ciphertext File",
            initialdir=init_dir,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.ct_var.set(path)

    def browse_wordlist(self):
        init_dir = os.path.join(get_app_dir(), "wls")
        if self.wl_var.get():
            d = os.path.dirname(self.wl_var.get())
            if os.path.isdir(d):
                init_dir = d
        path = filedialog.askopenfilename(
            title="Select Wordlist File",
            initialdir=init_dir,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.wl_var.set(path)

    def browse_iv_file(self):
        init_dir = os.path.join(get_app_dir(), "ivs")
        if self.iv_file_var.get():
            d = os.path.dirname(self.iv_file_var.get())
            if os.path.isdir(d):
                init_dir = d
        path = filedialog.askopenfilename(
            title="Select IV List File",
            initialdir=init_dir,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self.iv_file_var.set(path)

    # ── Logging ───────────────────────────────────────────────────────────

    def append_log(self, text):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_all(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")
        self._clear_results()

    def _clear_results(self):
        for row in self.result_rows:
            row.destroy()
        self.result_rows = []

    # ── Results Table ─────────────────────────────────────────────────────

    def _add_result_row(self, hit):
        row_frame = ctk.CTkFrame(self.results_scroll, fg_color="transparent", height=28)
        row_frame.pack(fill="x", pady=1)

        col_widths = [60, 120, 60, 110, 120, 100, 200]
        values = [
            f"{hit.get('score', 0):.1f}%",
            hit.get('cipher', ''),
            hit.get('mode', ''),
            hit.get('variant', 'original'),
            hit.get('key_ascii', ''),
            hit.get('iv_hex', '')[:24] + ('...' if len(hit.get('iv_hex', '')) > 24 else ''),
            hit.get('preview', '')[:60],
        ]

        score = hit.get('score', 0)
        if score >= 90:
            score_color = C["green"]
        elif score >= 75:
            score_color = C["yellow"]
        else:
            score_color = C["text"]

        for i, (w, val) in enumerate(zip(col_widths, values)):
            color = score_color if i == 0 else C["text"]
            lbl = ctk.CTkLabel(
                row_frame, text=val, width=w,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=color, anchor="w"
            )
            lbl.pack(side="left", padx=4)

        # Click to copy
        detail_text = (
            f"Score: {hit.get('score', 0):.2f}%\n"
            f"Cipher: {hit.get('cipher', '')}\n"
            f"Mode: {hit.get('mode', '')}\n"
            f"Variant: {hit.get('variant', 'original')}\n"
            f"Key (ASCII): {hit.get('key_ascii', '')}\n"
            f"Key (hex): {hit.get('key_hex', '')}\n"
            f"IV (hex): {hit.get('iv_hex', '')}\n"
            f"Preview: {hit.get('preview', '')}"
        )

        def on_click(event, text=detail_text):
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_label.configure(text="Result copied to clipboard", text_color=C["green"])
            self.after(2000, lambda: self.status_label.configure(text="Ready", text_color=C["dimmed"]))

        row_frame.bind("<Button-1>", on_click)
        for child in row_frame.winfo_children():
            child.bind("<Button-1>", on_click)

        self.result_rows.append(row_frame)

    # ── Timer ─────────────────────────────────────────────────────────────

    def _tick_timer(self):
        if self.start_time and (self.process or self._job_queue):
            elapsed = time.time() - self.start_time
            self.timer_label.configure(text=format_elapsed(elapsed))
            self.timer_id = self.after(1000, self._tick_timer)

    def _stop_timer(self):
        if self.timer_id:
            self.after_cancel(self.timer_id)
            self.timer_id = None

    # ── Resolve Inputs ────────────────────────────────────────────────────

    def _resolve_wordlist_path(self):
        if self.wl_mode.get() == "word":
            word = self.single_key_var.get().strip()
            if not word:
                return None
            import tempfile
            tmp_dir = os.path.join(tempfile.gettempdir(), "mcrypt_brute_tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            path = os.path.join(tmp_dir, "_single_key.txt")
            with open(path, "w") as f:
                f.write(word + "\n")
            return path
        else:
            p = self.wl_var.get().strip()
            return p if p and os.path.isfile(p) else None

    def _resolve_iv_path(self):
        mode = self.iv_mode.get()
        if mode == "zeros":
            return None  # PHP script uses all-zeros by default
        elif mode == "ascii_zeros":
            # 0x30 = ASCII '0', 32 bytes worth (oversized, backends truncate to fit)
            import tempfile
            tmp_dir = os.path.join(tempfile.gettempdir(), "mcrypt_brute_tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            path = os.path.join(tmp_dir, "_ascii_zeros_iv.txt")
            with open(path, "w") as f:
                f.write("30" * 32 + "\n")  # 32 bytes of 0x30 in hex
            return path
        elif mode == "single":
            iv_hex = self.single_iv_var.get().strip()
            if not iv_hex:
                return None
            import tempfile
            tmp_dir = os.path.join(tempfile.gettempdir(), "mcrypt_brute_tmp")
            os.makedirs(tmp_dir, exist_ok=True)
            path = os.path.join(tmp_dir, "_single_iv.txt")
            with open(path, "w") as f:
                f.write(iv_hex + "\n")
            return path
        elif mode == "file":
            p = self.iv_file_var.get().strip()
            return p if p and os.path.isfile(p) else None
        return None

    # ── Cracking Control ──────────────────────────────────────────────────

    def start_cracking(self):
        ct_path = self.ct_var.get().strip()
        if not ct_path or not os.path.isfile(ct_path):
            self.append_log("[ERROR] Please select a valid ciphertext file.\n")
            return

        wl_path = self._resolve_wordlist_path()
        if not wl_path:
            if self.wl_mode.get() == "word":
                self.append_log("[ERROR] Please enter a key to test.\n")
            else:
                self.append_log("[ERROR] Please select a valid wordlist file.\n")
            return

        # Gather selected ciphers
        selected_ciphers = [name for name, var in self.cipher_vars.items() if var.get()]
        if not selected_ciphers:
            self.append_log("[ERROR] Please select at least one cipher.\n")
            return

        selected_modes = [name for name, var in self.mode_vars.items() if var.get()]
        # XXTEA doesn't need standard modes; only require modes if non-XXTEA ciphers selected
        non_xxtea_selected = [c for c in selected_ciphers if c not in XXTEA_CIPHERS]
        if not selected_modes and non_xxtea_selected:
            self.append_log("[ERROR] Please select at least one mode.\n")
            return

        # Split ciphers by engine
        php_ciphers = [c for c in selected_ciphers if c in PHP_CIPHERS and c not in XXTEA_CIPHERS]
        xxtea_ciphers = [c for c in selected_ciphers if c in XXTEA_CIPHERS]
        py_ciphers = [c for c in selected_ciphers if c in PYCRYPTO_CIPHERS]
        cpp_ciphers = [c for c in selected_ciphers if c in CRYPTOPP_CIPHERS]

        # Warn about missing engines
        if (php_ciphers or xxtea_ciphers) and not self.php_path:
            self.append_log("[ERROR] php.exe not found — cannot run mcrypt/OpenSSL/XXTEA ciphers.\n")
            php_ciphers = []
            xxtea_ciphers = []
        if php_ciphers and not self.has_mcrypt:
            self.append_log("[ERROR] mcrypt extension not loaded — cannot run mcrypt ciphers.\n")
            php_ciphers = []
        ossl_selected = [c for c in php_ciphers if c in OPENSSL_CIPHERS]
        if ossl_selected and not self.has_openssl:
            self.append_log(f"[WARN] OpenSSL ciphers selected ({', '.join(ossl_selected)}) but OpenSSL extension not loaded — these will be skipped.\n")
        if py_ciphers and not self.has_pycryptodome:
            self.append_log("[WARN] PyCryptodome ciphers selected but PyCryptodome not installed — these will be skipped.\n")
            py_ciphers = []
        if cpp_ciphers and not self.has_cryptopp:
            self.append_log("[WARN] cryptopp_brute.exe not found — Crypto++ ciphers skipped.\n")
            cpp_ciphers = []

        if not php_ciphers and not xxtea_ciphers and not py_ciphers and not cpp_ciphers:
            self.append_log("[ERROR] No runnable ciphers selected.\n")
            return

        # Split modes: cfb-N variants are Crypto++ only
        standard_modes = [m for m in selected_modes if m not in CFB_MODES]
        cpp_extra_modes = [m for m in selected_modes if m in CFB_MODES]
        cpp_modes = standard_modes + cpp_extra_modes

        # Build common args (without --modes, added per-engine)
        common_args = ["--ct", ct_path, "--wl", wl_path]
        common_args += ["--encoding", self.encoding_var.get()]
        common_args += ["--threshold", str(self.threshold_var.get() / 100.0)]
        common_args += ["--top", self.topn_var.get()]
        common_args += ["--key-format", self.key_format_var.get()]
        if self.reverse_var.get():
            common_args += ["--reverse"]
        if self.caesar_var.get():
            common_args += ["--caesar"]
        if self.char_shift_var.get():
            common_args += ["--char-shift"]
        if self.reverse_key_var.get():
            common_args += ["--reverse-key"]
        if self.all_key_sizes_var.get():
            common_args += ["--all-key-sizes"]
        if self.repeat_key_var.get():
            common_args += ["--repeat-key"]
        iv_path = self._resolve_iv_path()
        if iv_path:
            common_args += ["--ivs", iv_path]

        # Build job queue
        self._job_queue = []
        if php_ciphers and standard_modes:
            script = os.path.join(get_app_dir(), "mcrypt_brute.php")
            cmd = [self.php_path, script] + common_args
            cmd += ["--modes", ",".join(standard_modes)]
            cmd += ["--ciphers", ",".join(php_ciphers)]
            self._job_queue.append(("mcrypt + OpenSSL", cmd))
        if xxtea_ciphers:
            # XXTEA is mode-independent — pass --modes xxtea (pseudo-mode)
            script = os.path.join(get_app_dir(), "mcrypt_brute.php")
            cmd = [self.php_path, script] + common_args
            cmd += ["--modes", "xxtea"]
            cmd += ["--ciphers", ",".join(xxtea_ciphers)]
            self._job_queue.append(("XXTEA", cmd))
        if py_ciphers and standard_modes:
            script = os.path.join(get_app_dir(), "pycrypto_brute.py")
            cmd = [self.python_path, script] + common_args
            cmd += ["--modes", ",".join(standard_modes)]
            cmd += ["--ciphers", ",".join(py_ciphers)]
            self._job_queue.append(("PyCryptodome", cmd))
        if cpp_ciphers and cpp_modes:
            cmd = [self.cryptopp_path] + common_args
            cmd += ["--modes", ",".join(cpp_modes)]
            cmd += ["--ciphers", ",".join(cpp_ciphers)]
            self._job_queue.append(("Crypto++", cmd))

        if not self._job_queue:
            self.append_log("[ERROR] No runnable cipher+mode combinations. "
                            "CFB variant modes (cfb-8..cfb-128) only work with Crypto++ ciphers.\n")
            return

        # Save config
        save_config({
            "ct_path": self.ct_var.get(),
            "encoding": self.encoding_var.get(),
            "wl_mode": self.wl_mode.get(),
            "single_key": self.single_key_var.get(),
            "wl_path": self.wl_var.get(),
            "key_format": self.key_format_var.get(),
            "iv_mode": self.iv_mode.get(),
            "single_iv": self.single_iv_var.get(),
            "iv_path": self.iv_file_var.get(),
            "ciphers": selected_ciphers,
            "modes": selected_modes,
            "threshold": self.threshold_var.get(),
            "top_n": self.topn_var.get(),
            "reverse": self.reverse_var.get(),
            "caesar": self.caesar_var.get(),
            "char_shift": self.char_shift_var.get(),
            "reverse_key": self.reverse_key_var.get(),
            "all_key_sizes": self.all_key_sizes_var.get(),
            "repeat_key": self.repeat_key_var.get(),
        })

        # UI state
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._clear_results()
        self.status_label.configure(text="Running...", text_color=C["accent"])
        self.progress.set(0)
        self._max_progress = 0.0

        self.start_time = time.time()
        self.timer_label.configure(text="0:00")
        self._tick_timer()

        self.stop_flag.clear()
        self._launch_next_job()

    def _launch_next_job(self):
        """Pop next job from queue and launch it."""
        if not self._job_queue:
            self.on_process_done()
            return

        engine_label, cmd = self._job_queue.pop(0)
        self.append_log(f"── Engine: {engine_label} ──\n")
        self._max_progress = 0.0
        self.progress.set(0)

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, bufsize=1,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0)
            )
        except Exception as e:
            self.append_log(f"[ERROR] Failed to start {engine_label}: {e}\n")
            self._launch_next_job()
            return

        self.reader_thread = threading.Thread(target=self.read_output, daemon=True)
        self.reader_thread.start()

    def stop_cracking(self):
        self.stop_flag.set()
        self._job_queue.clear()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass
        self.status_label.configure(text="Stopping...", text_color=C["orange"])

    def _read_stderr(self):
        """Read stderr in a separate thread — handles [PROGRESS] lines and surfaces errors."""
        try:
            for line in self.process.stderr:
                if self.stop_flag.is_set():
                    break
                line = line.rstrip('\n').rstrip('\r')
                prog_match = re.search(r'\[PROGRESS\]\s+([\d.]+)', line)
                if prog_match:
                    try:
                        value = float(prog_match.group(1))
                        value = max(0.0, min(1.0, value))
                        if value >= self._max_progress:
                            self._max_progress = value
                            self.after(0, self.progress.set, value)
                    except ValueError:
                        pass
                elif line.strip():
                    self.after(0, self.append_log, line + "\n")
        except Exception:
            pass

    def read_output(self):
        """Read stdout from the current process (stderr handled by separate thread)."""
        stderr_thread = threading.Thread(target=self._read_stderr, daemon=True)
        stderr_thread.start()

        json_buf = None

        try:
            for line in self.process.stdout:
                if self.stop_flag.is_set():
                    break

                line = line.rstrip('\n').rstrip('\r')

                # Collecting JSON block
                if json_buf is not None:
                    json_buf += line + "\n"
                    try:
                        data = json.loads(json_buf)
                        self.after(0, self._accumulate_results, data)
                        json_buf = None
                    except json.JSONDecodeError:
                        pass
                    continue

                if line.startswith("[RESULTS_JSON]"):
                    json_buf = ""
                    continue

                # Parse HIT lines for real-time results
                hit_match = re.match(
                    r'\[HIT\] score=([\d.]+) cipher=(\S+) mode=(\S+) variant=(\S+) key_hex=(\S+) iv_hex=(\S+) preview="(.*)"',
                    line
                )
                if hit_match:
                    hit = {
                        'score': float(hit_match.group(1)),
                        'cipher': hit_match.group(2),
                        'mode': hit_match.group(3),
                        'variant': hit_match.group(4),
                        'key_hex': hit_match.group(5),
                        'iv_hex': hit_match.group(6),
                        'preview': hit_match.group(7),
                        'key_ascii': '',
                    }
                    self.after(0, self._add_result_row, hit)

                self.after(0, self.append_log, line + "\n")
        except Exception:
            pass

        stderr_thread.join(timeout=5)
        self.process.wait()

        if self.stop_flag.is_set():
            self.after(0, lambda: self.status_label.configure(
                text="Stopped by user", text_color=C["orange"]))
            self.after(0, self.on_process_done)
        elif self._job_queue:
            # More jobs to run
            self.after(0, self._launch_next_job)
        else:
            hits = len(self.result_rows)
            if hits > 0:
                self.after(0, lambda: self.status_label.configure(
                    text=f"Finished — {hits} results found", text_color=C["green"]))
            else:
                self.after(0, lambda: self.status_label.configure(
                    text="Finished — no results above threshold", text_color=C["dimmed"]))
            self.after(0, self.on_process_done)

    def _accumulate_results(self, data):
        """Add results from a backend run (accumulates across multiple engines)."""
        for hit in data.get("results", []):
            self._add_result_row(hit)

        total = data.get("total_tested", 0)
        elapsed = data.get("elapsed", 0)
        self.append_log(f"\nTotal tested: {total:,}  Elapsed: {elapsed:.1f}s\n")

    def on_process_done(self):
        self.process = None
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        if self._max_progress >= 1.0:
            self.progress.set(1.0)
        self._stop_timer()

    def on_close(self):
        self._stop_timer()
        if self.process:
            try:
                self.process.terminate()
            except Exception:
                pass
        self.destroy()


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app = McryptBruteApp()
    app.mainloop()
