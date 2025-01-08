#!/usr/bin/env python3

# Brought to you by cryptic and tanbeer

import sys
from binascii import hexlify, unhexlify
from hashlib import sha384

from Crypto.Cipher import AES

IV_KEY = unhexlify("00000000000000000000000000000000")
# Default IV key for AES-CBC

def hexswap(input_hex: str):
    # Aka endian swap
    hex_pairs = [input_hex[i : i + 2] for i in range(0, len(input_hex), 2)]
    hex_rev = hex_pairs[::-1]
    hex_str = "".join(["".join(x) for x in hex_rev])
    return hex_str


def parse_nonce(nonce: str):
    # Hexswap then pad with 0s to 32
    return hexswap(nonce[:16]).encode().zfill(32)


def parse_key(key: bytes):
    # Split by 8 (4 bytes) and hexswap each segment, then join back together
    return "".join([hexswap(hexswap(key[i : i + 8].decode())) for i in range(0, len(key), 8)])


def entangle_nonce(key, nonce):
    # Encrypt the generator with AES-128-CBC with the AES key, then take a sha384 hash and substring to 64 characters to gives us the entangled nonce
    AES_CFG = AES.new(unhexlify(key), AES.MODE_CBC, IV_KEY)
    entangled_nonce = AES_CFG.encrypt(unhexlify(nonce))
    print("Encrypted Generator:", hexlify(entangled_nonce).decode())
    return hexlify(sha384(entangled_nonce).digest())[:-32]

def main():
    try:
        nonce = sys.argv[2] # user specified
        if len(sys.argv) > 2 and len(sys.argv[1]) == 32:
            key = hexlify(int(sys.argv[1], 16).to_bytes(16, 'big')) # user specified key dumped from x8A4 -k 0x8A3
            entangled_nonce = entangle_nonce(parse_key(key), parse_nonce(nonce)).decode()
            print(f"Entangled Nonce: {entangled_nonce}")
        else:
            print("Error: Invalid input, check that '0x' is stripped. Or check key/nonce!")
    except:
        print(f"Error: Expected 2 arguments, got {(len(sys.argv)-1)}")

if __name__ == "__main__":
    main()
