import math
import hashlib
import base64
import random

class DigitalSignature:
    def __init__(self, key_size=512):
        self.key_size = key_size
        self.bot_public, self.bot_private = self.generate_keys()
        self.user_public, self.user_private = self.generate_keys()

    def is_prime(self, n, k=20):
        """Teste de Miller-Rabin para primalidade"""
        if n < 2: return False
        for p in [2,3,5,7,11,13,17,19,23,29]:
            if n % p == 0: return n == p
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(k):
            a = random.randint(2, n-2)
            x = pow(a, d, n)
            if x == 1 or x == n-1: continue
            for __ in range(s-1):
                x = pow(x, 2, n)
                if x == n-1: break
            else: return False
        return True

    def generate_prime(self, bits):
        """Gera números primos grandes"""
        while True:
            p = random.getrandbits(bits)
            if p % 2 != 0 and self.is_prime(p):
                return p

    def extended_gcd(self, a, b):
        """Algoritmo de Euclides estendido"""
        if a == 0: return (b, 0, 1)
        else:
            g, y, x = self.extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def mod_inverse(self, a, m):
        """Inverso modular"""
        g, x, y = self.extended_gcd(a, m)
        if g != 1: raise ValueError('Modular inverse does not exist')
        return x % m

    def generate_keys(self, bits=None):
        """Gera par de chaves RSA"""
        bits = bits or self.key_size
        p = self.generate_prime(bits)
        q = self.generate_prime(bits)
        n = p * q
        phi = (p-1)*(q-1)
        e = 65537
        d = self.mod_inverse(e, phi)
        return (e, n), (d, n)

    def pss_sign(self, message, private_key, n_bits=1024):
        """Assina mensagem com RSA-PSS simplificado"""
        d, n = private_key
        h = hashlib.sha3_256(message.encode()).digest()
        h_int = int.from_bytes(h, 'big')
        salt = random.getrandbits(128).to_bytes(16, 'big')
        padded = (h_int << 128) | int.from_bytes(salt, 'big')
        signature = pow(padded, d, n)
        return base64.b64encode(signature.to_bytes(n_bits//8, 'big')).decode(), salt.hex()

    def pss_verify(self, message, signature_b64, public_key, salt_hex):
        """Verifica assinatura PSS"""
        e, n = public_key
        try:
            sig_bytes = base64.b64decode(signature_b64)
            sig_int = int.from_bytes(sig_bytes, 'big')
            decrypted = pow(sig_int, e, n)
            salt = int(salt_hex, 16)
            h_recv = decrypted >> 128
            h_real = int.from_bytes(hashlib.sha3_256(message.encode()).digest(), 'big')
            return h_recv == h_real
        except:
            return False