import math
import struct

def padding(msg_bits):
    PADDING = b"\x80" + 63 * b"\0"
    index = int((msg_bits >> 3) & 0x3f)
    if index < 56:
        padLen = (56 - index)
    else:
        padLen = (120 - index)
    return PADDING[:padLen] + bytes_encode((u32(msg_bits), msg_bits >> 32), 8)

def bytes_decode(input, len):
    k = len >> 2
    res = struct.unpack("I" * k, input)
    return list(res)

def bytes_encode(input, len):
    k = len >> 2
    res = struct.pack(*(("I" * k,) + tuple(input[:k])))
    return res

def F(b, c, d):
    return (b & c) | ((~b) & d)

def right_rotate(x, n):
    x = u32(x)
    return u32((x << (32 - n)) | (x >> n))

def u32(x):
    #return (x + (1 << 32)) % (1 << 32)
    #return x % 2**32
    return x & 0xffffffff

def reverse_a_unknown(a, b, c, d, x, s, K):
    old_b = b
    d, c, b = a, d, c
    a = right_rotate(old_b - b, s) - F(b, c, d) - K - x
    return u32(a), u32(b), u32(c), u32(d)

def reverse_block_unknown(a, b, c, d, init_state, s, K):
    old_b = b
    d, c, b = a, d, c
    x_msg = right_rotate(old_b - b, s) - F(b, c, d) - K - init_state
    return init_state, u32(b), u32(c), u32(d), u32(x_msg)

def reverse_md15(digest, rounds, block, s, K, init_states):
    a, b, c, d = bytes_decode(digest, len(digest))
    x = bytes_decode(block, len(block))
    x[:4] = [None] * 4
    a, b, c, d = u32(a - init_states[0]), u32(b - init_states[3]), u32(c - init_states[2]), u32(d - init_states[1])
    for i in range(rounds - 1, -1, -1):
        if x[i] != None:
            a, b, c, d = reverse_a_unknown(a, b, c, d, x[i], s[i], K[i])
        else:
            a, b, c, d, x[i] = reverse_block_unknown(a, b, c, d, init_states[i], s[i], K[i])
    block = bytes_encode(x, len(block))
    return block[:len(digest)]

if __name__ == "__main__":
    with open("md15", "rb") as f:
        f.seek(0xb007)
        digest = f.read(16)
    rounds = 12
    init_states = (0x67452301, 0x10325476, 0x98badcfe, 0xefcdab89) #a, d, c, b, ordered for rev
    s = (7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22)
    K = []
    for i in range(rounds):
        K.append(math.floor(2**32 * abs(math.sin(i + 1))))
    block = b"A" * len(digest) + padding(len(digest) * 8)
    data = reverse_md15(digest, rounds, block, s, K, init_states)
    text = bytes(x ^ ord("h") for x in data)
    print("hxp{%s}" % text.decode('ascii'))
