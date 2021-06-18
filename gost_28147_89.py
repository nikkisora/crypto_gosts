from utils import bit_length, int_to_str, str_to_int

_sbox = (
    (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3),
    (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9),
    (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11),
    (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3),
    (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2),
    (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14),
    (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12),
    (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12)
)

def _break_key(key):
    return [(key>>(32*i))&0xFFFFFFFF for i in range(8)]

def _break_msg(msg):
    return [(msg>>(64*i)) & 0xFFFFFFFFFFFFFFFF for i in reversed(range(bit_length(msg)//64+1))]

def _f(part, key):
    temp = part ^ key
    return_value = 0
    
    for i in range(8):
        return_value |= ((_sbox[i][(temp >> (4*i)) & 0xF]) << (4*i))
        
    return ((return_value >> 11) | (return_value << (21))) & 0xFFFFFFFF

def _block_encrypt(block, sub_keys):
    
    def _encryption_round(left, right, round_key):
        return right, left ^ _f(right, round_key)

    left = block >> 32
    right = block & 0xFFFFFFFF

    for i in range(24):
        left, right = _encryption_round(left, right, sub_keys[i%8])
    for i in reversed(range(8)):
        left, right = _encryption_round(left, right, sub_keys[i])

    return (left << 32) | right

def _block_decrypt(block, sub_keys):
    
    def _decryption_round(left, right, round_key):
        return right ^ _f(left, round_key), left

    left = block >> 32
    right = block & 0xFFFFFFFF

    for i in range(8):
        left, right = _decryption_round(left, right, sub_keys[i])
    for i in reversed(range(24)):
        left, right = _decryption_round(left, right, sub_keys[i%8])

    return  (left << 32) | right

#-----------------------ECB gost part 2-------------------

def encrypt_ECB(text, key):
    text_blocks = _break_msg(str_to_int(text))
    sub_keys = _break_key(key)
    return_value = 0
    
    for block in text_blocks:
        return_value = (return_value << 64) | _block_encrypt(block, sub_keys)
    
    return return_value

def decrypt_ECB(msg, key):
    msg_blocks = _break_msg(msg)
    sub_keys = _break_key(key)
    return_value = 0
    
    for block in msg_blocks:
        return_value = (return_value << 64) | _block_decrypt(block, sub_keys)
    
    return int_to_str(return_value)

#-----------------------CTR gost part 3-------------------
_C1 = int('1010104', 16)
_C2 = int('1010101', 16)

def _generate_gamma(n34):
    left = n34 >> 32
    right = n34 & 0xFFFFFFFF
    
    left = (left + _C2) % (2**32)
    right = (right + _C1) % (2**32-1)
    
    return (left << 32) | right

def _CTR(msg, key, synchrosignal):
    text_blocks = _break_msg(msg)
    sub_keys = _break_key(key)
    n34 = _block_encrypt(str_to_int(synchrosignal), sub_keys)
    return_value = 0

    for block in text_blocks:
        n34 = _generate_gamma(n34)
        gamma = _block_encrypt(n34, sub_keys)
        return_value = (return_value << 64) | (block ^ gamma)
        
    return return_value

def encrypt_CTR(text, key, synchrosignal):
    return _CTR(str_to_int(text), key, synchrosignal)

def decrypt_CTR(msg, key, synchrosignal):
    return int_to_str(_CTR(msg, key, synchrosignal))

#-----------------------CFB gost part 4-------------------

def encrypt_CFB(text, key, synchrosignal):
    text_blocks = _break_msg(str_to_int(text))
    sub_keys = _break_key(key)
    return_value = 0
    
    gamma = _block_encrypt(str_to_int(synchrosignal), sub_keys)

    for block in text_blocks:
        return_value = (return_value << 64) | (block ^ gamma)
        gamma = _block_encrypt(block ^ gamma, sub_keys)

    return return_value

def decrypt_CFB(msg, key, synchrosignal):
    text_blocks = _break_msg(msg)
    sub_keys = _break_key(key)
    return_value = 0
    
    gamma = _block_encrypt(str_to_int(synchrosignal), sub_keys)
    
    for block in text_blocks[1:]:
        return_value = (return_value << 64) | (block ^ gamma)
        gamma = _block_encrypt(block, sub_keys)
    
    return int_to_str(return_value)

#-----------------------CTR gost part 5-------------------

def generate_MAC(text, key, l):
    
    def _encryption_round(left, right, round_key):
        return right, left ^ _f(right, round_key)
    
    text_blocks = _break_msg(str_to_int(text))
    sub_keys = _break_key(key)
    return_value = 0
    
    for block in text_blocks:
        return_value ^= block
        
        left = return_value >> 32
        right = return_value & 0xFFFFFFFF

        for i in range(16):
            left, right = _encryption_round(left, right, sub_keys[i%8])
            
        return_value = (left << 32) | right
    
    return (return_value >> (32-l))&0xFFFFFFFF