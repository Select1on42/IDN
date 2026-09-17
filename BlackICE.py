import argparse
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import sys
import datetime
import secrets
import string
import hashlib
import hmac
import getpass

tcl_path = os.path.join(sys.base_prefix, 'tcl', 'tcl8.6')
tk_path = os.path.join(sys.base_prefix, 'tcl', 'tk8.6')
if os.path.exists(tcl_path):
    os.environ['TCL_LIBRARY'] = tcl_path
if os.path.exists(tk_path):
    os.environ['TK_LIBRARY'] = tk_path


# =========================================================
# ШИФР ЦЕЗАРЯ
# =========================================================
def caesar_cipher_file(input_path, output_path, shift, mode="encrypt"):
    if mode == "decrypt":
        shift = -shift
    try:
        with open(input_path, "rb") as f:
            data = f.read()
        result = bytearray()
        for byte in data:
            result.append((byte + shift) % 256)
        with open(output_path, "wb") as f:
            f.write(result)
        return True, None
    except Exception as e:
        return False, str(e)


# =========================================================
# ШИФР ВИЖЕНЕРА
# =========================================================
def Shifr_Vignera(input_path, output_path, key, mode="encrypt"):
    try:
        with open(input_path, 'rb') as f:
            n = f.read()
        lens = len(key)
        result = bytearray()
        for cnt, symb in enumerate(n):
            key_byte = ord(key[cnt % lens])
            if mode == 'encrypt':
                result.append((symb + key_byte) % 256)
            else:
                result.append((symb - key_byte) % 256)
        with open(output_path, "wb") as f:
            f.write(result)
        return True, None
    except Exception as e:
        return False, str(e)


# =========================================================
# ШИФР ПЕРЕСТАНОВКИ
# =========================================================
def Permutations_shifr(input_path, output_path, key, mode='decrypt', language='Russian'):
    if language == 'Russian':
        alfabet = ['А', 'Б', 'В', 'Г', 'Д', 'Е', 'Ё', 'Ж', 'З', 'И', 'Й', 'К', 'Л', 'М',
                   'Н', 'О', 'П', 'Р', 'С', 'Т', 'У', 'Ф', 'Х', 'Ц', 'Ч', 'Ш', 'Щ', 'Ъ',
                   'Ы', 'Ь', 'Э', 'Ю', 'Я']
    elif language == 'English':
        alfabet = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
                   'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

    dict_encrypt = dict(zip(alfabet, key))
    dict_decrypt = dict(zip(key, alfabet))
    dictionary = dict_encrypt if mode == 'encrypt' else dict_decrypt

    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            string = f.read()
        new_list = ''
        for symb in string:
            if symb in dictionary:
                new_list += dictionary[symb]
            else:
                new_list += symb
        with open(output_path, 'w', encoding='utf-8') as file_write:
            file_write.write(new_list)
        return True, None
    except Exception as e:
        return False, str(e)


# =========================================================
# ГОСТ Р 34.12-2015 "Магма"
# =========================================================
PI_MAGMA = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2]
]
MAGMA_BLOCK_SIZE = 8


def magma_get_keys(key_bytes):
    return [int.from_bytes(key_bytes[i:i + 4], 'big') for i in range(0, 32, 4)]


def magma_substitute(x):
    result = 0
    for i in range(8):
        nibble = (x >> (4 * i)) & 0x0F
        result |= PI_MAGMA[i][nibble] << (4 * i)
    return result & 0xFFFFFFFF


def magma_f(right, key):
    temp = (right + key) & 0xFFFFFFFF
    temp = magma_substitute(temp)
    return (((temp << 11) | (temp >> 21)) & 0xFFFFFFFF)


def magma_process_block(block, keys, encrypt=True):
    left = int.from_bytes(block[:4], 'big')
    right = int.from_bytes(block[4:], 'big')
    forward = list(range(8))
    backward = list(reversed(range(8)))
    schedule = forward * 3 + backward if encrypt else forward + backward * 3

    for i in range(32):
        key = keys[schedule[i]]
        new_left = right
        new_right = (left ^ magma_f(right, key)) & 0xFFFFFFFF
        left, right = new_left, new_right
    return right.to_bytes(4, 'big') + left.to_bytes(4, 'big')


def magma_pad(data):
    padding_len = MAGMA_BLOCK_SIZE - (len(data) % MAGMA_BLOCK_SIZE)
    return data + bytes([padding_len] * padding_len)


def magma_unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]


def magma_process_file(input_path, output_path, key_bytes, mode):
    try:
        keys = magma_get_keys(key_bytes)
        with open(input_path, 'rb') as file:
            data = file.read()

        result = bytearray()
        if mode == 'encrypt':
            data = magma_pad(data)
            for i in range(0, len(data), MAGMA_BLOCK_SIZE):
                block = data[i:i + MAGMA_BLOCK_SIZE]
                result.extend(magma_process_block(block, keys, True))
        else:
            for i in range(0, len(data), MAGMA_BLOCK_SIZE):
                block = data[i:i + MAGMA_BLOCK_SIZE]
                result.extend(magma_process_block(block, keys, False))
            result = magma_unpad(bytes(result))

        with open(output_path, 'wb') as file:
            file.write(result)
        return True, None
    except Exception as e:
        return False, str(e)


# =========================================================
# ГОСТ Р 34.12-2015 "Кузнечик"
# =========================================================
class Kuznyechik:
    Pi = (
        0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
        0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
        0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
        0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
        0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
        0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
        0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
        0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
        0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
        0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
        0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
        0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
        0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
        0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
        0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
        0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
    )
    l_vec = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)

    def init(self, key: bytes = None):
        self.reverse_Pi = bytearray(256)
        for i in range(256):
            self.reverse_Pi[self.Pi[i]] = i
        self.iter_C = self._generate_C()
        if key:
            self.keys = self.expand_keys(key)

    @staticmethod
    def multiply(a, b):
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi_bit = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit: a ^= 0xC3
            b >>= 1
        return p

    def X(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def S(self, data):
        return bytes(self.Pi[b] for b in data)

    def reverse_S(self, data):
        return bytes(self.reverse_Pi[b] for b in data)

    def R(self, state):
        a = 0
        for i in range(16): a ^= self.multiply(state[i], self.l_vec[i])
        return bytes([a]) + state[:-1]

    def L(self, data):
        res = data
        for _ in range(16): res = self.R(res)
        return res

    def reverse_R(self, state):
        a = state[0]
        for i in range(15): a ^= self.multiply(state[i + 1], self.l_vec[i])
        return state[1:] + bytes([a])

    def reverse_L(self, data):
        res = data
        for _ in range(16): res = self.reverse_R(res)
        return res

    def _generate_C(self):
        C = []
        for i in range(1, 33):
            block = bytes(15) + bytes([i])
            C.append(self.L(block))
        return C

    def F(self, key1, key2, const):
        internal = self.L(self.S(self.X(key1, const)))
        return self.X(internal, key2), key1

    def expand_keys(self, master_key):
        k1, k2 = master_key[:16], master_key[16:]
        keys = [k1, k2]
        for i in range(4):
            for j in range(8):
                k1, k2 = self.F(k1, k2, self.iter_C[i * 8 + j])
            keys.append(k1)
            keys.append(k2)
        return keys

    def encrypt(self, blk):
        out_blk = blk
        for i in range(9):
            out_blk = self.L(self.S(self.X(self.keys[i], out_blk)))
        return self.X(out_blk, self.keys[9])

    def decrypt(self, blk):
        out_blk = self.X(blk, self.keys[9])
        for i in range(8, -1, -1):
            out_blk = self.X(self.keys[i], self.reverse_S(self.reverse_L(out_blk)))
        return out_blk

    def process_file(self, input_path, output_path, key: bytes, mode: str):
        try:
            self.init(key)
            with open(input_path, "rb") as f:
                data = f.read()

            result = bytearray()
            if mode == 'encrypt':
                pad_len = 16 - (len(data) % 16)
                data += bytes([pad_len] * pad_len)
                for i in range(0, len(data), 16):
                    result += self.encrypt(data[i:i + 16])
            else:
                for i in range(0, len(data), 16):
                    result += self.decrypt(data[i:i + 16])
                result = result[:-result[-1]]

            with open(output_path, "wb") as f:
                f.write(result)
            return True, None
        except Exception as e:
            return False, str(e)


# =========================================================
# AES-128/256 (ECB Mode, PKCS#7)
# =========================================================
AES_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]
AES_RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
AES_INV_SBOX = [0] * 256
for idx in range(256):
    AES_INV_SBOX[AES_SBOX[idx]] = idx


def aes_rot_word(word): return word[1:] + word[:1]


def aes_sub_word(word): return [AES_SBOX[b] for b in word]


def aes_xtime(a): return ((a << 1) ^ 0x11B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def aes_gf_mult(a, b):
    p = 0
    for _ in range(8):
        if b & 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set: a ^= 0x11B
        a &= 0xFF
        b >>= 1
    return p


def aes_key_expansion(key):
    Nk = len(key) // 4
    Nr = 10 if Nk == 4 else 14
    w = []
    for i in range(Nk): w.append(list(key[4 * i: 4 * i + 4]))
    for i in range(Nk, 4 * (Nr + 1)):
        temp = w[i - 1][:]
        if i % Nk == 0:
            temp = aes_sub_word(aes_rot_word(temp))
            temp[0] ^= AES_RCON[i // Nk]
        elif Nk > 6 and i % Nk == 4:
            temp = aes_sub_word(temp)
        w.append([w[i - Nk][x] ^ temp[x] for x in range(4)])
    return w


def aes_add_round_key(state, w, round_idx):
    for c in range(4):
        for r in range(4): state[r][c] ^= w[round_idx * 4 + c][r]


def aes_sub_bytes(state):
    for r in range(4):
        for c in range(4): state[r][c] = AES_SBOX[state[r][c]]


def aes_shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]


def aes_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        t = col[0] ^ col[1] ^ col[2] ^ col[3]
        u = col[0]
        col[0] ^= t ^ aes_xtime(col[0] ^ col[1])
        col[1] ^= t ^ aes_xtime(col[1] ^ col[2])
        col[2] ^= t ^ aes_xtime(col[2] ^ col[3])
        col[3] ^= t ^ aes_xtime(col[3] ^ u)
        for r in range(4): state[r][c] = col[r]


def aes_inv_sub_bytes(state):
    for r in range(4):
        for c in range(4): state[r][c] = AES_INV_SBOX[state[r][c]]


def aes_inv_shift_rows(state):
    state[1] = state[1][-1:] + state[1][:-1]
    state[2] = state[2][-2:] + state[2][:-2]
    state[3] = state[3][-3:] + state[3][:-3]


def aes_inv_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = aes_gf_mult(col[0], 0x0e) ^ aes_gf_mult(col[1], 0x0b) ^ aes_gf_mult(col[2], 0x0d) ^ aes_gf_mult(
            col[3], 0x09)
        state[1][c] = aes_gf_mult(col[0], 0x09) ^ aes_gf_mult(col[1], 0x0e) ^ aes_gf_mult(col[2], 0x0b) ^ aes_gf_mult(
            col[3], 0x0d)
        state[2][c] = aes_gf_mult(col[0], 0x0d) ^ aes_gf_mult(col[1], 0x09) ^ aes_gf_mult(col[2], 0x0e) ^ aes_gf_mult(
            col[3], 0x0b)
        state[3][c] = aes_gf_mult(col[0], 0x0b) ^ aes_gf_mult(col[1], 0x0d) ^ aes_gf_mult(col[2], 0x09) ^ aes_gf_mult(
            col[3], 0x0e)


def aes_encrypt_block(plaintext, key):
    Nk = len(key) // 4
    Nr = 10 if Nk == 4 else 14
    state = [[plaintext[r + 4 * c] for c in range(4)] for r in range(4)]
    w = aes_key_expansion(key)
    aes_add_round_key(state, w, 0)
    for i in range(1, Nr):
        aes_sub_bytes(state)
        aes_shift_rows(state)
        aes_mix_columns(state)
        aes_add_round_key(state, w, i)
    aes_sub_bytes(state)
    aes_shift_rows(state)
    aes_add_round_key(state, w, Nr)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def aes_decrypt_block(ciphertext, key):
    Nk = len(key) // 4
    Nr = 10 if Nk == 4 else 14
    state = [[ciphertext[r + 4 * c] for c in range(4)] for r in range(4)]
    w = aes_key_expansion(key)
    aes_add_round_key(state, w, Nr)
    for i in range(Nr - 1, 0, -1):
        aes_inv_shift_rows(state)
        aes_inv_sub_bytes(state)
        aes_add_round_key(state, w, i)
        aes_inv_mix_columns(state)
    aes_inv_shift_rows(state)
    aes_inv_sub_bytes(state)
    aes_add_round_key(state, w, 0)
    return bytes(state[r][c] for c in range(4) for r in range(4))


def aes_process_file(input_path, output_path, key_bytes, mode):
    try:
        with open(input_path, 'rb') as f:
            data = f.read()

        result = bytearray()
        if mode == 'encrypt':
            pad_len = 16 - (len(data) % 16)
            padded = data + bytes([pad_len] * pad_len)
            for i in range(0, len(padded), 16):
                result.extend(aes_encrypt_block(padded[i:i + 16], key_bytes))
        else:
            if len(data) % 16 != 0:
                return False, "Длина шифротекста должна быть кратна 16 байтам."
            for i in range(0, len(data), 16):
                result.extend(aes_decrypt_block(data[i:i + 16], key_bytes))
            pad_len = result[-1]
            if not (1 <= pad_len <= 16) or result[-pad_len:] != bytes([pad_len] * pad_len):
                return False, "Некорректный PKCS#7 паддинг"
            result = result[:-pad_len]

        with open(output_path, 'wb') as f:
            f.write(result)
        return True, None
    except Exception as e:
        return False, str(e)


# =========================================================
# СИСТЕМА ЛОГИРОВАНИЯ
# =========================================================
# Папка данных приложения. По умолчанию рядом с .py/.exe.
# Можно задать отдельно через переменную окружения TAILAND_DATA_DIR.
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR = os.path.abspath(os.environ.get("TAILAND_DATA_DIR", APP_DIR))
os.makedirs(DATA_DIR, exist_ok=True)
LOG_FILE = os.path.join(DATA_DIR, "app_logs.txt")
ADMIN_PASSWORD_FILE = os.path.join(DATA_DIR, "admin_password.dat")
PASSWORD_ITERATIONS = 200_000

def set_data_dir(path: str):
    """Переназначает папку хранения журнала и файла пароля."""
    global DATA_DIR, LOG_FILE, ADMIN_PASSWORD_FILE
    DATA_DIR = os.path.abspath(os.path.expanduser(path))
    os.makedirs(DATA_DIR, exist_ok=True)
    LOG_FILE = os.path.join(DATA_DIR, "app_logs.txt")
    ADMIN_PASSWORD_FILE = os.path.join(DATA_DIR, "admin_password.dat")


# =========================================================
# ПАРОЛЬ АДМИНИСТРАТОРА
# =========================================================
def _password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )


def is_admin_password_initialized() -> bool:
    return os.path.isfile(ADMIN_PASSWORD_FILE)


def set_admin_password(password: str):
    """Создаёт/перезаписывает пароль администратора в виде salt+hash."""
    if len(password) < 6:
        return False, "Пароль должен содержать минимум 6 символов."
    salt = secrets.token_bytes(16)
    digest = _password_digest(password, salt)
    try:
        with open(ADMIN_PASSWORD_FILE, "w", encoding="ascii") as f:
            f.write(salt.hex() + ":" + digest.hex())
        return True, None
    except Exception as e:
        return False, str(e)


def verify_admin_password(password: str) -> bool:
    """Проверяет пароль по сохранённой соли и хешу."""
    try:
        with open(ADMIN_PASSWORD_FILE, "r", encoding="ascii") as f:
            raw = f.read().strip()
        salt_hex, digest_hex = raw.split(":", 1)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = _password_digest(password, salt)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _safe_log_text(value):
    """Не позволяет переносу строки сломать структуру журнала."""
    if value is None:
        return ""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


def add_log(cipher: str, mode: str, file_path: str, status: str,
            details: str = "", access: str = "USER"):
    """Записывает событие в общий журнал.

    access=USER — запись видит обычный пользователь и администратор.
    access=ADMIN — запись видит только администратор.
    Секретные ключи/пароли в журнал никогда не записываются.
    """
    access = "ADMIN" if str(access).upper() == "ADMIN" else "USER"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.basename(file_path) if file_path else "—"
    cipher = _safe_log_text(cipher)
    mode = _safe_log_text(mode)
    status = _safe_log_text(status)
    filename = _safe_log_text(filename)
    details = _safe_log_text(details)

    log_line = (
        f"[{timestamp}] | Доступ: {access:<5} | Алгоритм: {cipher:<11} | "
        f"Режим: {mode:<16} | Статус: {status:<7} | Файл: {filename}"
        f"{f' | {details}' if details else ''}\n"
    )

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Ошибка записи лога: {e}")


def read_logs(access="USER"):
    """Читает общий журнал с разграничением доступа."""
    try:
        if not os.path.exists(LOG_FILE):
            return "Файл логов пока пуст."
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if str(access).upper() == "ADMIN":
            visible = lines
        else:
            visible = [line for line in lines if "| Доступ: USER" in line]

        content = "".join(visible)
        return content if content else "Для этого уровня доступа записей пока нет."
    except Exception as e:
        return f"Ошибка чтения логов: {e}"


def clear_log_file():
    """Очищает общий журнал и возвращает (успех, ошибка)."""
    try:
        with open(LOG_FILE, "w", encoding="utf-8"):
            pass
        return True, None
    except Exception as e:
        return False, str(e)


def _safe_log_text(value):
    """Не позволяет переносу строки сломать структуру журнала."""
    if value is None:
        return ""
    return str(value).replace("\r", " ").replace("\n", " ").strip()


# =========================================================
# ИНТЕРФЕЙС GUI
# =========================================================
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Шифратор файлов v1.3")
        self.geometry("580x680")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")

        self.file_path = ""
        self.output_dir = ""
        self.kuznechik = Kuznyechik()

        # --- Шапка: Заголовок и Выбор темы ---
        self.top_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.top_frame.pack(fill="x", padx=20, pady=(15, 5))

        self.label = ctk.CTkLabel(
            self.top_frame, text="Шифратор файлов", font=("Arial", 22, "bold")
        )
        self.label.pack(side="left")

        self.theme_menu = ctk.CTkOptionMenu(
            self.top_frame, values=["Dark", "Light"], command=self.change_theme, width=100
        )
        self.theme_menu.pack(side="right")
        self.theme_menu.set("Dark")

        # --- Блок 1: Выбор алгоритма ---
        self.cipher_frame = ctk.CTkFrame(self)
        self.cipher_frame.pack(fill="x", padx=20, pady=10)

        self.cipher_label = ctk.CTkLabel(
            self.cipher_frame, text="Алгоритм шифрования:", font=("Arial", 13, "bold")
        )
        self.cipher_label.pack(anchor="w", padx=15, pady=(10, 5))

        self.cipher_menu = ctk.CTkOptionMenu(
            self.cipher_frame,
            values=["Цезарь", "Виженер", "Перестановка", "Magma", "Kuznechik", "AES"],
            command=self.on_cipher_change,
            width=250
        )
        self.cipher_menu.pack(anchor="w", padx=15, pady=(0, 10))

        # --- Блок 2: Файлы и Пути ---
        self.file_frame = ctk.CTkFrame(self)
        self.file_frame.pack(fill="x", padx=20, pady=5)

        # Выбор входного файла
        self.file_button = ctk.CTkButton(
            self.file_frame, text="Выбрать файл", command=self.select_file, width=160
        )
        self.file_button.grid(row=0, column=0, padx=15, pady=10, sticky="w")

        self.path_label = ctk.CTkLabel(self.file_frame, text="Файл не выбран", text_color="gray", anchor="w")
        self.path_label.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        # Выбор папки назначения
        self.dir_button = ctk.CTkButton(
            self.file_frame, text="Папка сохранения", command=self.select_output_dir, width=160
        )
        self.dir_button.grid(row=1, column=0, padx=15, pady=(0, 10), sticky="w")

        self.dir_label = ctk.CTkLabel(
            self.file_frame, text="По умолчанию (рядом с файлом)", text_color="gray", anchor="w"
        )
        self.dir_label.grid(row=1, column=1, padx=10, pady=(0, 10), sticky="ew")

        self.file_frame.grid_columnconfigure(1, weight=1)

        # Изменение кода для генерации пароля
        # --- Блок 3: Ключ шифрования ---
        self.key_frame = ctk.CTkFrame(self)
        self.key_frame.pack(fill="x", padx=20, pady=10)

        self.key_header_frame = ctk.CTkFrame(self.key_frame, fg_color="transparent")
        self.key_header_frame.pack(fill="x", padx=15, pady=(10, 2))

        self.key_info_label = ctk.CTkLabel(
            self.key_header_frame, text="Формат ключа: Число",
            font=("Arial", 12), text_color="silver"
        )
        self.key_info_label.pack(side="left")

        # Показывается только для AES и определяет размер генерируемого ключа.
        self.aes_size_menu = ctk.CTkOptionMenu(
            self.key_header_frame,
            values=["AES-128", "AES-256"],
            width=110
        )
        self.aes_size_menu.set("AES-256")

        # Контейнер для поля ввода и кнопки
        self.key_input_frame = ctk.CTkFrame(self.key_frame, fg_color="transparent")
        self.key_input_frame.pack(fill="x", padx=15, pady=(0, 15))

        self.shift_entry = ctk.CTkEntry(
            self.key_input_frame, placeholder_text="Введите или сгенерируйте ключ...", height=35
        )
        self.shift_entry.pack(side="left", expand=True, fill="x", padx=(0, 10))

        self.gen_key_button = ctk.CTkButton(
            self.key_input_frame, text="🎲 Сгенерировать", width=130, height=35,
            command=self.generate_key
        )
        self.gen_key_button.pack(side="right")

        # Кнопка копировать
        self.copy_key_button = ctk.CTkButton(
            self.key_input_frame,
            text="📋 Копировать",
            width=110,
            height=35,
            command=self.copy_key
        )
        self.copy_key_button.pack(side="right", padx=(5, 0))

        # --- Блок 4: Основные действия ---
        self.action_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.action_frame.pack(fill="x", padx=20, pady=15)

        self.enc_button = ctk.CTkButton(
            self.action_frame, text="Зашифровать", fg_color="#2EA043", hover_color="#238636",
            height=40, font=("Arial", 14, "bold"),
            command=lambda: self.process("encrypt"),
        )
        self.enc_button.pack(side="left", expand=True, fill="x", padx=(0, 5))

        self.dec_button = ctk.CTkButton(
            self.action_frame, text="Расшифровать", fg_color="#1F6FEB", hover_color="#1158C7",
            height=40, font=("Arial", 14, "bold"),
            command=lambda: self.process("decrypt"),
        )
        self.dec_button.pack(side="right", expand=True, fill="x", padx=(5, 0))

        # --- Подвал: Журналы ---
        self.log_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.log_frame.pack(side="bottom", fill="x", padx=20, pady=15)

        self.user_log_button = ctk.CTkButton(
            self.log_frame, text="Журнал операций", border_width=1,
            command=self.show_user_logs_window
        )
        self.user_log_button.pack(side="left", expand=True, fill="x", padx=(0, 5))

        self.log_button = ctk.CTkButton(
            self.log_frame, text="Журнал администратора", border_width=1,
            command=self.open_logs_with_auth
        )
        self.log_button.pack(side="right", expand=True, fill="x", padx=(5, 0))

        # Первичная настройка пароля выполняется после создания окна.
        self.after(150, self.check_admin_password_setup)

    def copy_key(self):
        key = self.shift_entry.get()
        if key:
            self.clipboard_clear()
            self.clipboard_append(key)
            self.update()
            messagebox.showinfo("Успех", "Ключ скопирован в буфер обмена!")
        else:
            messagebox.showwarning("Внимание", "Поле ключа пустое!")

    def change_theme(self, theme):
        ctk.set_appearance_mode(theme)

    def on_cipher_change(self, cipher):
        self.aes_size_menu.pack_forget()
        if cipher == "Виженер":
            self.key_info_label.configure(text="Формат ключа: Слово")
        elif cipher == "Перестановка":
            self.key_info_label.configure(text="Формат ключа: 33 символа алфавита (Рус)")
        elif cipher in ["Magma", "Kuznechik"]:
            self.key_info_label.configure(text="Формат ключа: Hex-ключ (64 символа / 256 бит)")
        elif cipher == "AES":
            self.key_info_label.configure(text="Формат ключа: Hex-ключ (32/64 символа для AES-128/256)")
            self.aes_size_menu.pack(side="right")
        else:
            self.key_info_label.configure(text="Формат ключа: Число")

    # Генерация ключа — используется и GUI, и терминалом
    def generate_key(self):
        cipher = self.cipher_menu.get()
        aes_bits = 128 if self.aes_size_menu.get() == "AES-128" else 256
        key = generate_key_for_cipher(cipher, aes_bits)

        self.shift_entry.delete(0, "end")
        self.shift_entry.insert(0, key)
        # Сам ключ не записываем — только факт генерации и его длину.
        add_log("Система", "generate_key", "", "УСПЕХ",
                f"Алгоритм: {cipher}; длина ключа: {len(key)} символов", "USER")

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            filename = os.path.basename(self.file_path)
            display_name = filename if len(filename) < 30 else filename[:27] + "..."
            self.path_label.configure(
                text=display_name, text_color=("black", "white")
            )

    def select_output_dir(self):
        selected_dir = filedialog.askdirectory()
        if selected_dir:
            self.output_dir = selected_dir
            display_path = selected_dir if len(selected_dir) < 30 else "..." + selected_dir[-27:]
            self.dir_label.configure(text=display_path, text_color=("black", "white"))

    def check_admin_password_setup(self):
        if is_admin_password_initialized():
            return
        self.create_admin_password_dialog(first_setup=True)

    def create_admin_password_dialog(self, first_setup=False):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Первичная настройка" if first_setup else "Смена пароля")
        dialog.geometry("430x300" if first_setup else "430x380")
        dialog.resizable(False, False)
        dialog.transient(self)
        dialog.grab_set()

        title = "Создание пароля администратора" if first_setup else "Смена пароля администратора"
        ctk.CTkLabel(dialog, text=title, font=("Arial", 18, "bold")).pack(pady=(25, 15))

        if not first_setup:
            ctk.CTkLabel(dialog, text="Старый пароль:").pack(anchor="w", padx=35)
            old_entry = ctk.CTkEntry(dialog, show="*", width=360)
            old_entry.pack(pady=(5, 12))

        ctk.CTkLabel(dialog, text="Новый пароль:").pack(anchor="w", padx=35)
        new_entry = ctk.CTkEntry(dialog, show="*", width=360)
        new_entry.pack(pady=(5, 12))

        ctk.CTkLabel(dialog, text="Повторите новый пароль:").pack(anchor="w", padx=35)
        confirm_entry = ctk.CTkEntry(dialog, show="*", width=360)
        confirm_entry.pack(pady=(5, 15))

        def save_password():
            if not first_setup and not verify_admin_password(old_entry.get()):
                add_log("Система", "password_change", "", "ОШИБКА",
                        "Неверный старый пароль", "ADMIN")
                messagebox.showerror("Ошибка", "Неверный старый пароль.", parent=dialog)
                return

            new_password = new_entry.get()
            confirm_password = confirm_entry.get()
            if new_password != confirm_password:
                messagebox.showerror("Ошибка", "Новые пароли не совпадают.", parent=dialog)
                return
            if len(new_password) < 6:
                messagebox.showerror("Ошибка", "Пароль должен содержать минимум 6 символов.", parent=dialog)
                return

            success, error = set_admin_password(new_password)
            if not success:
                messagebox.showerror("Ошибка", error, parent=dialog)
                return

            action = "admin_password_created" if first_setup else "admin_password_changed"
            add_log("Система", action, "", "УСПЕХ", "Пароль администратора сохранён", "ADMIN")
            messagebox.showinfo(
                "Успех",
                "Пароль администратора успешно создан." if first_setup else "Пароль администратора успешно изменён.",
                parent=dialog,
            )
            dialog.destroy()

        ctk.CTkButton(dialog, text="Сохранить", command=save_password).pack(pady=5)
        if not first_setup:
            ctk.CTkButton(dialog, text="Отмена", fg_color="transparent", border_width=1,
                          command=dialog.destroy).pack(pady=5)

        self.wait_window(dialog)

    def open_logs_with_auth(self):
        dialog = ctk.CTkInputDialog(text="Введите пароль администратора:", title="Доступ к логам")
        password = dialog.get_input()

        if password is None:
            return

        if verify_admin_password(password):
            add_log("Система", "admin_login", "", "УСПЕХ", "Администратор открыл расширенный журнал", "ADMIN")
            self.show_logs_window()
        else:
            add_log("Система", "admin_login", "", "ОШИБКА", "Неверный пароль администратора", "ADMIN")
            messagebox.showerror("Ошибка доступа", "Неверный пароль администратора!")

    def show_user_logs_window(self):
        log_win = ctk.CTkToplevel(self)
        log_win.title("Журнал операций")
        log_win.geometry("760x500")
        log_win.grab_set()

        textbox = ctk.CTkTextbox(log_win, width=730, height=400, font=("Consolas", 12))
        textbox.pack(pady=10, padx=10)
        textbox.insert("1.0", read_logs("USER"))
        textbox.configure(state="disabled")

        ctk.CTkButton(log_win, text="Обновить", command=lambda: self.refresh_log_textbox(textbox, "USER")).pack(pady=5)

    def show_logs_window(self):
        log_win = ctk.CTkToplevel(self)
        log_win.title("Журнал администратора (все записи)")
        log_win.geometry("800x560")
        log_win.grab_set()

        textbox = ctk.CTkTextbox(log_win, width=770, height=420, font=("Consolas", 12))
        textbox.pack(pady=10, padx=10)
        textbox.insert("1.0", read_logs("ADMIN"))
        textbox.configure(state="disabled")

        buttons = ctk.CTkFrame(log_win, fg_color="transparent")
        buttons.pack(pady=5)

        ctk.CTkButton(buttons, text="Обновить", command=lambda: self.refresh_log_textbox(textbox, "ADMIN")).pack(side="left", padx=5)
        ctk.CTkButton(buttons, text="Сменить пароль", command=self.create_admin_password_dialog).pack(side="left", padx=5)
        ctk.CTkButton(buttons, text="Очистить общий журнал", fg_color="#D32F2F", hover_color="#B71C1C",
                      command=lambda: self.clear_logs_from_window(textbox)).pack(side="left", padx=5)

    def refresh_log_textbox(self, textbox, access):
        textbox.configure(state="normal")
        textbox.delete("1.0", "end")
        textbox.insert("1.0", read_logs(access))
        textbox.configure(state="disabled")

    def clear_logs_from_window(self, textbox):
        if not messagebox.askyesno("Подтверждение", "Очистить весь общий журнал?", parent=textbox.winfo_toplevel()):
            return
        success, error = clear_log_file()
        if success:
            add_log("Система", "clear_logs", "", "УСПЕХ", "Администратор очистил общий журнал", "ADMIN")
        else:
            add_log("Система", "clear_logs", "", "ОШИБКА", f"Ошибка очистки: {error}", "ADMIN")
        self.refresh_log_textbox(textbox, "ADMIN")
        if not success:
            messagebox.showerror("Ошибка", f"Не удалось очистить журнал:\n{error}")

    def process(self, mode):
        cipher = self.cipher_menu.get()
        if not self.file_path:
            add_log(cipher, mode, "", "ОШИБКА", "Файл не выбран")
            messagebox.showwarning("Внимание", "Сначала выберите файл!")
            return

        key_raw = self.shift_entry.get()
        if not key_raw:
            add_log(cipher, mode, self.file_path, "ОШИБКА", "Ключ не может быть пустым")
            messagebox.showerror("Ошибка", "Ключ не может быть пустым!")
            return

        folder = self.output_dir if self.output_dir else os.path.dirname(self.file_path)
        name = os.path.basename(self.file_path)
        output_path = os.path.join(folder, f"{mode}_{name}")

        success, error_msg = False, "Неизвестная ошибка"

        if cipher == "Цезарь":
            try:
                shift = int(key_raw)
            except ValueError:
                messagebox.showerror("Ошибка", "Для шифра Цезаря ключ должен быть числом!")
                return
            success, error_msg = caesar_cipher_file(self.file_path, output_path, shift, mode)

        elif cipher == "Виженер":
            success, error_msg = Shifr_Vignera(self.file_path, output_path, key_raw, mode)

        elif cipher == "Перестановка":
            if len(key_raw) != 33:
                messagebox.showerror("Ошибка", "Для русского языка ключ должен содержать ровно 33 символа!")
                return
            key_list = list(key_raw.upper())
            success, error_msg = Permutations_shifr(self.file_path, output_path, key_list, mode, 'Russian')

        elif cipher in ["Magma", "Kuznechik"]:
            try:
                key_bytes = bytes.fromhex(key_raw)
                if len(key_bytes) != 32:
                    messagebox.showerror("Ошибка", "Длина ключа должна быть ровно 32 байта (64 hex-символа).")
                    return
            except ValueError:
                messagebox.showerror("Ошибка", "Ключ должен быть корректной шестнадцатеричной строкой (hex).")
                return

            if cipher == "Magma":
                success, error_msg = magma_process_file(self.file_path, output_path, key_bytes, mode)
            else:
                success, error_msg = self.kuznechik.process_file(self.file_path, output_path, key_bytes, mode)

        elif cipher == "AES":
            try:
                key_bytes = bytes.fromhex(key_raw)
                if len(key_bytes) not in [16, 32]:
                    messagebox.showerror("Ошибка", "Для AES ключ должен быть 16 байт (32 hex) или 32 байта (64 hex).")
                    return
            except ValueError:
                messagebox.showerror("Ошибка", "Ключ должен быть корректной шестнадцатеричной строкой (hex).")
                return

            success, error_msg = aes_process_file(self.file_path, output_path, key_bytes, mode)

        if success:
            add_log(cipher, mode, self.file_path, "УСПЕХ", f"Результат: {output_path}")
            messagebox.showinfo("Успех", f"Файл сохранен как:\n{output_path}")
        else:
            add_log(cipher, mode, self.file_path, "ОШИБКА", error_msg)
            messagebox.showerror("Ошибка", f"Что-то пошло не так:\n{error_msg}")


# =========================================================
# ГЕНЕРАЦИЯ КЛЮЧЕЙ И РАБОТА ЧЕРЕЗ ТЕРМИНАЛ
# =========================================================

def generate_key_for_cipher(cipher, aes_bits=256):
    """Генерирует ключ тем же способом, что и кнопка генерации в GUI."""
    if cipher == "Цезарь":
        return str(secrets.randbelow(255) + 1)
    if cipher == "Виженер":
        chars = string.ascii_letters + string.digits
        return "".join(secrets.choice(chars) for _ in range(16))
    if cipher == "Перестановка":
        alphabet = list("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")
        secrets.SystemRandom().shuffle(alphabet)
        return "".join(alphabet)
    if cipher in ("Magma", "Kuznechik"):
        return secrets.token_hex(32)
    if cipher == "AES":
        if aes_bits not in (128, 256):
            raise ValueError("Размер ключа AES должен быть 128 или 256 бит.")
        return secrets.token_hex(aes_bits // 8)
    raise ValueError(f"Неизвестный алгоритм: {cipher}")


def normalize_cipher_name(cipher):
    aliases = {
        "caesar": "Цезарь", "cesar": "Цезарь", "цезарь": "Цезарь",
        "vigenere": "Виженер", "vigenère": "Виженер", "виженер": "Виженер",
        "permutation": "Перестановка", "перестановка": "Перестановка",
        "magma": "Magma",
        "kuznyechik": "Kuznechik", "kuznechik": "Kuznechik", "кузнечик": "Kuznechik",
        "aes": "AES",
    }
    name = cipher.strip().lower()
    if name not in aliases:
        raise ValueError(
            f"Неизвестный алгоритм: {cipher}. "
            f"Доступны: caesar, vigenere, permutation, magma, kuznyechik, aes."
        )
    return aliases[name]


def ensure_admin_password_cli():
    """При первом запуске через терминал просит создать пароль администратора."""
    if is_admin_password_initialized():
        return True

    print("Первый запуск: необходимо создать пароль администратора.")
    while True:
        try:
            password = getpass.getpass("Создайте пароль (минимум 6 символов): ")
            confirm = getpass.getpass("Повторите пароль: ")
        except (EOFError, KeyboardInterrupt):
            print("\nНастройка пароля отменена.")
            return False

        if password != confirm:
            print("Ошибка: пароли не совпадают.")
            continue
        success, error = set_admin_password(password)
        if not success:
            print(f"Ошибка: {error}")
            continue
        add_log("Система", "admin_password_created", "", "УСПЕХ", "Пароль администратора создан", "ADMIN")
        print("Пароль администратора успешно создан.")
        return True


def show_logs_cli(admin=False):
    """Показывает журнал в терминале."""
    access = "ADMIN" if admin else "USER"
    content = read_logs(access)
    print("\n===== ЖУРНАЛ ЛОГОВ =====")
    print(f"Папка данных: {DATA_DIR}")
    print(f"Файл журнала: {LOG_FILE}")
    print(content)
    print("===== КОНЕЦ ЖУРНАЛА =====")
    add_log("Система", "view_logs_cli", "", "УСПЕХ",
            f"Просмотр журнала; уровень: {access}", access)


def change_admin_password_cli():
    if not verify_admin_password(getpass.getpass("Старый пароль: ")):
        add_log("Система", "password_change", "", "ОШИБКА", "Неверный старый пароль", "ADMIN")
        print("Ошибка: неверный старый пароль.")
        return False

    new_password = getpass.getpass("Новый пароль (минимум 6 символов): ")
    confirm = getpass.getpass("Повторите новый пароль: ")
    if new_password != confirm:
        print("Ошибка: новые пароли не совпадают.")
        return False

    success, error = set_admin_password(new_password)
    if not success:
        print(f"Ошибка: {error}")
        return False
    add_log("Система", "admin_password_changed", "", "УСПЕХ", "Пароль администратора изменён", "ADMIN")
    print("Пароль администратора успешно изменён.")
    return True


def run_cli():
    parser = argparse.ArgumentParser(
        description="Шифратор файлов: GUI + терминальный режим."
    )
    parser.add_argument(
        "cipher", nargs="?",
        help="Алгоритм: caesar, vigenere, permutation, magma, kuznyechik, aes; для смены пароля: admin"
    )
    parser.add_argument(
        "mode", nargs="?", choices=["encrypt", "decrypt", "generate", "password", "logs"],
        help="Режим: encrypt, decrypt, generate, logs или password"
    )
    parser.add_argument("-i", "--input", help="Путь к исходному файлу")
    parser.add_argument("-o", "--output", help="Путь к выходному файлу")
    parser.add_argument("-k", "--key", help="Ключ. Для generate не нужен")
    parser.add_argument(
        "--aes-size", type=int, choices=[128, 256],
        help="Размер генерируемого AES-ключа: 128 или 256 бит (по умолчанию 256)"
    )
    parser.add_argument(
        "--data-dir",
        help="Отдельная папка для app_logs.txt и admin_password.dat. "
             "Также можно использовать TAILAND_DATA_DIR."
    )

    args = parser.parse_args()

    if args.data_dir:
        try:
            set_data_dir(args.data_dir)
        except OSError as e:
            parser.error(f"Не удалось создать папку данных: {e}")

    if args.cipher == "logs" and args.mode is None:
        show_logs_cli(False)
        return

    if args.cipher == "admin" and args.mode == "logs":
        if not ensure_admin_password_cli():
            return
        if not verify_admin_password(getpass.getpass("Пароль администратора: ")):
            add_log("Система", "view_logs_cli", "", "ОШИБКА", "Неверный пароль", "ADMIN")
            print("Ошибка: неверный пароль администратора.")
            return
        show_logs_cli(True)
        return

    if args.cipher == "admin" and args.mode == "password":
        if not ensure_admin_password_cli():
            return
        change_admin_password_cli()
        return
    if not args.cipher or not args.mode:
        parser.error("Укажите алгоритм и режим. Журнал: logs; админ-журнал: admin logs; смена пароля: admin password")

    try:
        cipher = normalize_cipher_name(args.cipher)
    except ValueError as e:
        parser.error(str(e))

    if args.mode == "generate":
        if args.input or args.output or args.key:
            parser.error("В режиме generate параметры -i, -o и -k не используются.")
        if args.aes_size is not None and cipher != "AES":
            parser.error("--aes-size можно использовать только с алгоритмом AES.")
        aes_bits = args.aes_size if args.aes_size is not None else 256
        key = generate_key_for_cipher(cipher, aes_bits)
        add_log("Система", "generate_key_cli", "", "УСПЕХ",
                f"Алгоритм: {cipher}; длина ключа: {len(key)} символов")
        print(f"Алгоритм: {cipher}")
        print(f"Сгенерированный ключ: {key}")
        return

    if not args.input:
        add_log(cipher, args.mode, "", "ОШИБКА", "Не указан входной файл")
        parser.error("Для encrypt/decrypt необходимо указать -i/--input.")
    if not args.key:
        add_log(cipher, args.mode, args.input, "ОШИБКА", "Ключ не указан")
        parser.error("Для encrypt/decrypt необходимо указать -k/--key.")
    if not os.path.isfile(args.input):
        add_log(cipher, args.mode, args.input, "ОШИБКА", "Входной файл не найден")
        parser.error(f"Входной файл не найден: {args.input}")

    key_raw = args.key
    output_path = args.output
    if not output_path:
        directory = os.path.dirname(os.path.abspath(args.input))
        filename = os.path.basename(args.input)
        output_path = os.path.join(directory, f"{args.mode}_{filename}")

    success, error_msg = False, "Неизвестная ошибка"

    if cipher == "Цезарь":
        try:
            shift = int(key_raw)
        except ValueError:
            add_log(cipher, args.mode, args.input, "ОШИБКА", "Ключ Цезаря не является числом")
            parser.error("Для шифра Цезаря ключ должен быть целым числом.")
        success, error_msg = caesar_cipher_file(args.input, output_path, shift, args.mode)

    elif cipher == "Виженер":
        success, error_msg = Shifr_Vignera(args.input, output_path, key_raw, args.mode)

    elif cipher == "Перестановка":
        if len(key_raw) != 33:
            add_log(cipher, args.mode, args.input, "ОШИБКА", "Ключ перестановки должен содержать 33 символа")
            parser.error("Для русского языка ключ перестановки должен содержать ровно 33 символа.")
        key_list = list(key_raw.upper())
        alphabet = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
        if sorted(key_list) != sorted(alphabet):
            add_log(cipher, args.mode, args.input, "ОШИБКА", "Ключ перестановки содержит неверный набор букв")
            parser.error(
                "Ключ перестановки должен содержать все 33 буквы русского алфавита "
                "ровно по одному разу."
            )
        success, error_msg = Permutations_shifr(
            args.input, output_path, key_list, args.mode, "Russian"
        )

    elif cipher in ("Magma", "Kuznechik"):
        try:
            key_bytes = bytes.fromhex(key_raw)
        except ValueError:
            add_log(cipher, args.mode, args.input, "ОШИБКА", "Некорректный hex-ключ")
            parser.error("Ключ должен быть корректной шестнадцатеричной строкой (hex).")
        if len(key_bytes) != 32:
            add_log(cipher, args.mode, args.input, "ОШИБКА", "Неверная длина ключа: требуется 32 байта")
            parser.error(
                "Для Magma/Kuznechik ключ должен быть ровно 32 байта (64 hex-символа)."
            )
        if cipher == "Magma":
            success, error_msg = magma_process_file(
                args.input, output_path, key_bytes, args.mode
            )
        else:
            success, error_msg = Kuznyechik().process_file(
                args.input, output_path, key_bytes, args.mode
            )

    elif cipher == "AES":
        try:
            key_bytes = bytes.fromhex(key_raw)
        except ValueError:
            add_log(cipher, args.mode, args.input, "ОШИБКА", "Некорректный AES hex-ключ")
            parser.error("Ключ должен быть корректной шестнадцатеричной строкой (hex).")
        if len(key_bytes) not in (16, 32):
            add_log(cipher, args.mode, args.input, "ОШИБКА", "Неверная длина AES-ключа: требуется 16 или 32 байта")
            parser.error(
                "Для AES ключ должен быть 16 байт (32 hex-символа) "
                "или 32 байта (64 hex-символа)."
            )
        success, error_msg = aes_process_file(
            args.input, output_path, key_bytes, args.mode
        )

    if success:
        add_log(cipher, args.mode, args.input, "УСПЕХ", f"Результат: {output_path}")
        print(f"Успешно. Файл сохранен: {output_path}")
    else:
        add_log(cipher, args.mode, args.input, "ОШИБКА", error_msg)
        print(f"Ошибка: {error_msg}")
        sys.exit(1)


if __name__ == "__main__":
    # С аргументами запускается терминальный режим, без аргументов — GUI.
    if len(sys.argv) > 1:
        run_cli()
    else:
        app = App()
        app.mainloop()