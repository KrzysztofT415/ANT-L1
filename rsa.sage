from sage.crypto.util import bin_to_ascii, ascii_to_bin
import random
import string
ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits

def randomUTF8Message(l):
    return ''.join(random.choices(ALPHABET, k=l))

def keyGen(p_length, q_length):
    # P&Q generation
    p_max, p_min = pow(2, p_length) - 1, pow(2, p_length - 1)
    q_max, q_min = pow(2, q_length) - 1, pow(2, q_length - 1)
    p = random_prime(p_max, lbound=p_min)
    q = random_prime(q_max, lbound=q_min)

    # PublicKey
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        e = ZZ.random_element(phi)
        if gcd(e, phi) == 1:
            break
    pk = (e, n)

    # SecretKey
    dp = inverse_mod(e, p-1)
    dq = inverse_mod(e, q-1)
    q_inv = inverse_mod(q, p)
    sk = (p, q, dp, dq, q_inv)

    return pk, sk

def encrypt(m, pk):
    s = (pk[1].nbits() // 8) + 1
    c = [encrypt_block(m[i:i+s], pk) for i in range(0, len(m), s)]
    return c

def encrypt_block(m, pk):
    e, n = pk
    m = int.from_bytes(m, 'big')
    c = power_mod(m, e, n)
    c = str(bin_to_ascii('0' * (8 - len(c.binary()) % 8) + c.binary()))
    return bytes(c, "utf-8")

def decrypt(c, sk):
    m = [decrypt_block(cb, sk) for cb in c]
    m = b"".join(m)
    return m

def decrypt_block(c, sk):
    p, q, dp, dq, q_inv = sk
    c = int(str(ascii_to_bin(c.decode("utf-8"))), 2)
    m1 = power_mod(c, dp, p)
    m2 = power_mod(c, dq, q)
    h = (m1 - m2) * q_inv % p
    m = m2 + q * h
    m = bin_to_ascii('0' * (8 - len(m.binary()) % 8) + m.binary())
    return bytes(m, "utf-8")

pk, sk = keyGen(1024, 1024)
m = bytes(randomUTF8Message(1025), "utf-8")
print(m)
print("--")
c = encrypt(m, pk)
print(c)
print("--")
d = decrypt(c, sk)
print(d)
if m == d:
    print("same")
else:
    print("different")