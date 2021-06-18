def bit_length(value):
    return len(bin(value)[2:])

def str_to_int(text):
    return int.from_bytes(str.encode(text), byteorder='little')

def bytes_to_int(bytes):
    return int.from_bytes(bytes, byteorder='little')

def int_to_str(number):
    return number.to_bytes(int(bit_length(number)/8)+1, 'little').decode()

def mod_invert(a, n):
    if a < 0:
        return n - mod_invert(-a, n)
    t, new_t = 0, 1
    r, new_r = n, a
    while new_r != 0:
        quotinent = r // new_r
        t, new_t = new_t, t - quotinent * new_t
        r, new_r = new_r, r - quotinent * new_r
    if r > 1:
        return -1
    if t < 0:
        t = t + n
    return t
   