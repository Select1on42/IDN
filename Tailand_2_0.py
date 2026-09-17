import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import sys
import datetime
import secrets
import string

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


LOG_FILE = "app_logs.txt"
ADMIN_PASSWORD = "admin"  # Пароль для доступа к логам


def add_log(cipher: str, mode: str, file_path: str, status: str, details: str = ""):
    """Запись события в файл логов (создается рядом со скриптом)."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.basename(file_path) if file_path else "—"
    log_line = f"[{timestamp}] | Алгоритм: {cipher:<11} | Режим: {mode:<7} | Статус: {status:<7} | Файл: {filename} {f'({details})' if details else ''}\n"

    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_line)
    except Exception as e:
        print(f"Ошибка записи лога: {e}")


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

        self.key_info_label = ctk.CTkLabel(
            self.key_frame, text="Формат ключа: Число", font=("Arial", 12), text_color="silver"
        )
        self.key_info_label.pack(anchor="w", padx=15, pady=(10, 2))

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

        # --- Подвал: Администрирование ---
        self.log_button = ctk.CTkButton(
            self, text="Журнал операций (Админ)", fg_color="transparent", border_width=1,
            text_color=("gray10", "gray90"), hover_color=("#E5E5E5", "#333333"),
            command=self.open_logs_with_auth
        )
        self.log_button.pack(side="bottom", pady=15)

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
        if cipher == "Виженер":
            self.key_info_label.configure(text="Формат ключа: Слово")
        elif cipher == "Перестановка":
            self.key_info_label.configure(text="Формат ключа: 33 символа алфавита (Рус)")
        elif cipher in ["Magma", "Kuznechik"]:
            self.key_info_label.configure(text="Формат ключа: Hex-ключ (64 символа / 256 бит)")
        elif cipher == "AES":
            self.key_info_label.configure(text="Формат ключа: Hex-ключ (32/64 символа для AES-128/256)")
        else:
            self.key_info_label.configure(text="Формат ключа: Число")

# Новое добавление - Генерация пароль
    def generate_key(self):
        cipher = self.cipher_menu.get()

        if cipher == "Цезарь":
            # Случайное число сдвига от 1 до 255
            key = str(secrets.randbelow(255) + 1)

        elif cipher == "Виженер":
            # Случайное слово/пароль из 16 букв и цифр
            chars = string.ascii_letters + string.digits
            key = "".join(secrets.choice(chars) for _ in range(16))

        elif cipher == "Перестановка":
            # Перемешанные 33 буквы русского алфавита
            alphabet = list("АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ")
            secrets.SystemRandom().shuffle(alphabet)
            key = "".join(alphabet)

        elif cipher in ["Magma", "Kuznechik"]:
            # 32 байта в hex (64 символа)
            key = secrets.token_hex(32)

        elif cipher == "AES":
            # 32 байта в hex для AES-256 (64 символа)
            key = secrets.token_hex(32)
        else:
            key = ""

        # Запись сгенерированного ключа в поле ввода
        self.shift_entry.delete(0, "end")
        self.shift_entry.insert(0, key)

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

    def open_logs_with_auth(self):
        dialog = ctk.CTkInputDialog(text="Введите пароль администратора:", title="Доступ к логам")
        password = dialog.get_input()

        if password is None:
            return

        if password == ADMIN_PASSWORD:
            self.show_logs_window()
        else:
            messagebox.showerror("Ошибка доступа", "Неверный пароль администратора!")

    def show_logs_window(self):
        log_win = ctk.CTkToplevel(self)
        log_win.title("Журнал операций (Логи)")
        log_win.geometry("720x450")
        log_win.grab_set()

        textbox = ctk.CTkTextbox(log_win, width=690, height=340, font=("Consolas", 12))
        textbox.pack(pady=10, padx=10)

        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                textbox.insert("1.0", f.read())
        else:
            textbox.insert("1.0", "Файл логов пока пуст.")

        textbox.configure(state="disabled")

        def clear_logs():
            if messagebox.askyesno("Подтверждение", "Вы уверены, что хотите очистить все логи?"):
                open(LOG_FILE, "w", encoding="utf-8").close()
                textbox.configure(state="normal")
                textbox.delete("1.0", "end")
                textbox.insert("1.0", "Логи успешно очищены.")
                textbox.configure(state="disabled")

        clear_btn = ctk.CTkButton(log_win, text="Очистить логи", fg_color="#D32F2F", hover_color="#B71C1C",
                                  command=clear_logs)
        clear_btn.pack(pady=5)

    def process(self, mode):
        cipher = self.cipher_menu.get()
        if not self.file_path:
            messagebox.showwarning("Внимание", "Сначала выберите файл!")
            return

        key_raw = self.shift_entry.get()
        if not key_raw:
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
            add_log(cipher, mode, self.file_path, "УСПЕХ")
            messagebox.showinfo("Успех", f"Файл сохранен как:\n{output_path}")
        else:
            add_log(cipher, mode, self.file_path, "ОШИБКА", error_msg)
            messagebox.showerror("Ошибка", f"Что-то пошло не так:\n{error_msg}")


if __name__ == "__main__":
    app = App()
    app.mainloop()