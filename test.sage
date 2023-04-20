import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
import imp
rsa = imp.load_source('rsa.sage', 'rsa.sage.py')
import random
import string
ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits

def randomUTF8Message(l):
    return ''.join(random.choices(ALPHABET, k=l))

print("Starting hello test")
pk, sk = rsa.keyGen(1024, 1024)
m = b"HelloWorld"
c = rsa.encrypt(m, pk)
d = rsa.decrypt(c, sk)
if (d != m):
    raise Exception('ERROR in hello test ', d, m)
print("Hello test passed")

print("Starting bulk tests")
for i in range(4):
    pk, sk = rsa.keyGen(1024, 1024)
    for j in range(8):
        m = bytes(randomUTF8Message(random.randrange(512, 2048)), "utf-8")
        c = rsa.encrypt(m, pk)
        d = rsa.decrypt(c, sk)
        if (d != m):
            raise Exception('ERROR in test ', i, j, d, m)
print("All tests ended successfully")