"""Weak RSA and Ed25519 public keys for the key check tests: Fermat-factorable,
ROCA-structured, a small factor, a low-order Ed25519 point. Test tool only.
usage: weak_keys.py <output dir>"""
import base64, random, struct, sys
out = sys.argv[1]
rng = random.Random(42)
def is_prime(n):
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29,31,37]:
        if n % p == 0: return n == p
    d, s = n - 1, 0
    while d % 2 == 0: d //= 2; s += 1
    for _ in range(24):
        a = rng.randrange(2, n - 1); x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else: return False
    return True
def next_prime(n):
    n |= 1
    while not is_prime(n): n += 2
    return n
def mpint(n):
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big')
    return struct.pack('>I', len(b)) + b
def string(b): return struct.pack('>I', len(b)) + b
def rsa_pub(n, e=65537, comment='weak'):
    blob = string(b'ssh-rsa') + mpint(e) + mpint(n)
    return f"ssh-rsa {base64.b64encode(blob).decode()} {comment}\n"
p = next_prime(rng.getrandbits(1024) | (1 << 1023))
open(f'{out}/fermat.pub', 'w').write(rsa_pub(p * next_prime(p + 2), comment='fermat'))
primes = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167]
M = 1
for q in primes: M *= q
def roca_prime():
    while True:
        r = rng.getrandbits(1024) | (1 << 1023)
        cand = (r // M) * M + pow(65537, rng.randrange(1, 10**6), M)
        if cand.bit_length() == 1024 and is_prime(cand): return cand
while True:
    n = roca_prime() * roca_prime()
    if n.bit_length() == 2048: break
open(f'{out}/roca.pub', 'w').write(rsa_pub(n, comment='roca'))
q = next_prime(rng.getrandbits(2046) | (1 << 2045))
open(f'{out}/smallfactor.pub', 'w').write(rsa_pub(3 * q, comment='small-factor'))
ident = (1).to_bytes(32, 'little')
blob = string(b'ssh-ed25519') + string(ident)
open(f'{out}/lowed.pub', 'w').write(f"ssh-ed25519 {base64.b64encode(blob).decode()} low-order\n")
