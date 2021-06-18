from gost_3411_2012 import gost_hash
from utils import mod_invert, bytes_to_int
from collections import namedtuple
import random

Curve = namedtuple('Curve', ['p', 'q', 'a', 'b', 'P_x', 'P_y'])

_gost_curve = Curve(
    int('8000000000000000000000000000000000000000000000000000000000000431', 16),
    int('8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3', 16),
    int('7', 16),
    int('5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E', 16),
    int('2', 16),
    int('8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8', 16)
)

def _add_points(x1, y1, x2, y2, curve:Curve):
    if x1 == x2 and y1 == y2:
        lmbd = ((3 * x1**2 + curve.a) * mod_invert((y1 * 2), curve.p)) % curve.p
    else:
        lmbd = ((y1 - y2) * mod_invert(x1 - x2, curve.p)) % curve.p
    x3 = (lmbd**2 - x1 - x2) % curve.p
    y3 = (lmbd * (x1 - x3) - y1) % curve.p
    return x3, y3

def _multiply_point(k, curve:Curve, x=None, y=None):
    x = x if x else curve.P_x
    y = y if y else curve.P_y
    res_x = x
    res_y = y
    k -= 1
    while k:
        if k & 1:
            res_x, res_y = _add_points(res_x, res_y, x, y, curve)
        x, y = _add_points(x, y, x, y, curve)
        k >>= 1
    return res_x, res_y

def sign(message, key_d, curve:Curve = _gost_curve):
    
    hash = gost_hash(message)
    
    e = hash % curve.q
    if not e:
        e = 1
        
    while True:
        k = random.SystemRandom().randint(1, curve.q-1)
        
        r, _ = _multiply_point(k, curve)
        r %= curve.q
        if not r:
            continue
        
        s = (r * key_d + k * e)%curve.q
        if not s:
            continue
        break    
    
    return r, s

def get_public_key(key_d, curve = _gost_curve):
    return _multiply_point(key_d, curve)

def verify(message, zeta, verification_key, curve:Curve = _gost_curve):
    r, s = zeta
    q = curve.q
    
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    
    hash = gost_hash(message)
    e = hash % q
    if not e:
        e = 1
        
    v = mod_invert(e, q)
    
    z1 = s * v % q
    z2 = -r * v % q
    
    p1x, p1y = _multiply_point(z1, curve)
    q1x, q1y = _multiply_point(z2, curve, verification_key[0], verification_key[1])
    x, _ = _add_points(p1x, p1y, q1x, q1y, curve)
    
    R = x % q
    
    return R == r