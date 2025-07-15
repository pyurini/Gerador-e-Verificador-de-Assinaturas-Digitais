import math
import hashlib
import base64
import random
from typing import Tuple

class DigitalSignature:
    """
    Implementa um sistema de assinatura digital RSA-PSS para mensagens.
    Gera pares de chaves RSA e provê métodos para assinar e verificar mensagens.
    """
    def __init__(self, key_size=2048):
        """
        Inicializa o sistema de assinatura.
        Gera pares de chaves para o bot e para um usuário de exemplo.
        Define funções de hash e comprimento do salt.
        """
        self.key_size = key_size
        # Gera chaves para o bot
        self.bot_public, self.bot_private = self.generate_keys()
        # Gera chaves para um usuário de exemplo (para assinar mensagens do usuário)
        self.user_public, self.user_private = self.generate_keys()
        
        # Funções de hash para PSS (SHA3-256 é uma boa escolha moderna)
        self.hash_func = hashlib.sha3_256
        self.mgf_hash = hashlib.sha3_256
        self.salt_length = 32  # Tamanho do salt em bytes (recomendado para SHA3-256)

    def is_prime(self, n: int, k: int = 20) -> bool:
        """
        Teste de Miller-Rabin para verificar se um número é primo.
        'n': O número a ser testado.
        'k': Número de iterações para o teste de Miller-Rabin (maior k = maior certeza).
        """
        if n < 2 or n % 2 == 0:
            return False
        
        # Teste para pequenos primos conhecidos para otimização
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
        for p in small_primes:
            if n % p == 0:
                return n == p
        
        # Escreve n-1 como d * 2^s
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        
        # Teste de Miller-Rabin
        for _ in range(k):
            a = random.randint(2, n - 2) # Escolhe um 'a' aleatório
            x = pow(a, d, n) # Calcula a^d mod n
            if x == 1 or x == n - 1:
                continue # Provavelmente primo
            for __ in range(s - 1):
                x = pow(x, 2, n) # x = x^2 mod n
                if x == n - 1:
                    break # Provavelmente primo
            else:
                return False # Composto
        return True # Provavelmente primo

    def generate_prime(self, bits: int) -> int:
        """
        Gera um número primo grande com um número específico de bits.
        Usa o teste de Miller-Rabin para verificar a primalidade.
        """
        while True:
            p = random.getrandbits(bits) # Gera um número aleatório com 'bits'
            # Garante que o número seja ímpar e tenha o bit mais significativo setado
            p |= (1 << bits - 1) | 1 
            if self.is_prime(p):
                return p

    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        Implementa o Algoritmo de Euclides Estendido para encontrar gcd(a, b) e coeficientes x, y
        tais que ax + by = gcd(a, b).
        """
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.extended_gcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def mod_inverse(self, a: int, m: int) -> int:
        """
        Calcula o inverso modular de 'a' modulo 'm'.
        Ou seja, encontra 'x' tal que (a * x) % m == 1.
        """
        g, x, y = self.extended_gcd(a, m)
        if g != 1:
            raise ValueError('Modular inverse does not exist') # Inverso não existe se gcd(a,m) != 1
        return x % m

    def generate_keys(self, bits: int = None) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """
        Gera um par de chaves RSA (chave pública e chave privada).
        'bits': O tamanho total da chave em bits (default é self.key_size).
        Retorna: (chave_publica (e, n), chave_privada (d, n))
        """
        bits = bits or self.key_size
        # Gera dois primos grandes e distintos
        p = self.generate_prime(bits // 2)
        q = self.generate_prime(bits // 2)
        
        while p == q: # Garante que p e q são diferentes
            q = self.generate_prime(bits // 2)
        
        n = p * q # Módulo
        phi = (p - 1) * (q - 1) # Função totiente de Euler
        e = 65537 # Expoente público comum (um primo grande)
        
        # Garante que 'e' e 'phi' são coprimos
        while math.gcd(e, phi) != 1:
            # Se não forem, regera p, q e phi (raro, mas garante a validade)
            p = self.generate_prime(bits // 2)
            q = self.generate_prime(bits // 2)
            n = p * q
            phi = (p - 1) * (q - 1)
        
        d = self.mod_inverse(e, phi) # Expoente privado
        return (e, n), (d, n)

    def mgf1(self, seed: bytes, length: int) -> bytes:
        """
        MGF1 (Mask Generation Function) conforme especificado em PKCS#1 v2.1.
        'seed': O input para a função de geração de máscara.
        'length': O comprimento desejado da máscara em bytes.
        """
        counter = 0
        output = b''
        while len(output) < length:
            # Concatena o seed com um contador e faz o hash
            C = seed + counter.to_bytes(4, 'big')
            output += self.mgf_hash(C).digest()
            counter += 1
        return output[:length] # Retorna apenas o comprimento desejado

    def emsa_pss_encode(self, message: bytes, em_bits: int) -> bytes:
        """
        Codificação EMSA-PSS (Encoding Method for Signature with Appendix - Probabilistic Signature Scheme).
        Prepara a mensagem para ser assinada com RSA.
        'message': A mensagem original em bytes.
        'em_bits': O número de bits do módulo RSA (n.bit_length() - 1).
        """
        m_hash = self.hash_func(message).digest() # Hash da mensagem
        h_len = len(m_hash) # Comprimento do hash
        s_len = self.salt_length # Comprimento do salt
        em_len = (em_bits + 7) // 8 # Comprimento do bloco codificado em bytes
        
        # Passo 1 e 2: Verifica o comprimento
        if em_len < h_len + s_len + 2:
            raise ValueError("Encoding error: Output block too short")
        
        # Passo 3: Gera um salt aleatório
        salt = random.randbytes(s_len)
        
        # Passo 4: Concatena 8 bytes zero, o hash da mensagem e o salt
        M_prime = b'\x00' * 8 + m_hash + salt
        
        # Passo 5: Calcula o hash de M_prime
        H = self.hash_func(M_prime).digest()
        
        # Passo 6: Cria o padding string (PS)
        PS = b'\x00' * (em_len - s_len - h_len - 2)
        
        # Passo 7: Concatena PS, 0x01 e salt para formar DB
        DB = PS + b'\x01' + salt
        
        # Passo 8: Gera a máscara db_mask usando MGF1
        db_mask = self.mgf1(H, em_len - h_len - 1)
        
        # Passo 9: Aplica XOR entre DB e db_mask
        masked_db = bytes([db_mask[i] ^ DB[i] for i in range(len(DB))])
        
        # Passo 10: Ajusta o bit mais significativo do masked_db (se necessário)
        # O bit mais significativo do masked_db é ajustado para zero
        # para garantir que o valor inteiro resultante não exceda o módulo n.
        # em_bits é o tamanho efetivo do módulo menos 1 bit.
        # (8 * em_len - em_bits) é o número de bits não utilizados no byte mais significativo.
        # O (0xFF >> N) cria uma máscara para zerar os N bits mais significativos.
        masked_db = bytes([masked_db[0] & (0xFF >> (8 * em_len - em_bits))]) + masked_db[1:]
        
        # Passo 11: Concatena masked_db, H e o byte final 0xbc
        EM = masked_db + H + b'\xbc'
        
        return EM

    def emsa_pss_verify(self, message: bytes, EM: bytes, em_bits: int) -> bool:
        """
        Verificação EMSA-PSS.
        Verifica se um bloco codificado (EM) corresponde à mensagem original.
        'message': A mensagem original em bytes.
        'EM': O bloco codificado a ser verificado.
        'em_bits': O número de bits do módulo RSA (n.bit_length() - 1).
        """
        m_hash = self.hash_func(message).digest() # Hash da mensagem original
        h_len = len(m_hash) # Comprimento do hash
        s_len = self.salt_length # Comprimento do salt
        em_len = (em_bits + 7) // 8 # Comprimento do bloco codificado em bytes
        
        # Passo 1 e 2: Verifica o comprimento
        if em_len < h_len + s_len + 2:
            return False
        
        # Passo 3: Verifica o byte final (trailer)
        if EM[-1:] != b'\xbc':
            return False
        
        # Passo 4: Separa masked_db e H do EM
        masked_db = EM[:em_len - h_len - 1]
        H = EM[em_len - h_len - 1:-1]
        
        # Passo 5: Verifica o bit mais significativo do masked_db
        if masked_db[0] >> (8 - (8 * em_len - em_bits)) != 0:
            return False
        
        # Passo 6: Gera a máscara db_mask usando MGF1
        db_mask = self.mgf1(H, em_len - h_len - 1)
        
        # Passo 7: Aplica XOR entre masked_db e db_mask para recuperar DB
        DB = bytes([db_mask[i] ^ masked_db[i] for i in range(len(masked_db))])
        # Ajusta o bit mais significativo do DB (se necessário)
        DB = bytes([DB[0] & (0xFF >> (8 * em_len - em_bits))]) + DB[1:]
        
        # Passo 8: Verifica o padding string (PS) e o byte 0x01
        PS_len = em_len - h_len - s_len - 2
        if DB[:PS_len] != b'\x00' * PS_len or DB[PS_len] != 0x01:
            return False
        
        # Passo 9: Extrai o salt do DB
        salt = DB[PS_len + 1:]
        
        # Passo 10: Concatena 8 bytes zero, o hash da mensagem original e o salt
        M_prime = b'\x00' * 8 + m_hash + salt
        
        # Passo 11: Calcula o hash de M_prime
        H_prime = self.hash_func(M_prime).digest()
        
        # Passo 12: Compara H e H_prime para verificar a assinatura
        return H == H_prime

    def pss_sign(self, message: str, private_key: Tuple[int, int]) -> Tuple[str, str]:
        """
        Assina uma mensagem usando o esquema RSA-PSS.
        'message': A mensagem a ser assinada (string).
        'private_key': A chave privada RSA (d, n).
        Retorna: Uma tupla (assinatura_em_base64, salt_em_base64_vazio).
                 O salt não é mais retornado separadamente, mas mantemos a tupla
                 para compatibilidade com a assinatura anterior.
        """
        d, n = private_key
        em_bits = n.bit_length() - 1 # Tamanho efetivo do módulo em bits
        message_bytes = message.encode('utf-8') # Codifica a mensagem para bytes
        
        # Codificação EMSA-PSS para preparar a mensagem para a operação RSA
        EM = self.emsa_pss_encode(message_bytes, em_bits)
        m_int = int.from_bytes(EM, 'big') # Converte o bloco codificado para inteiro
        
        # Operação de assinatura RSA (elevação à potência 'd' modulo 'n')
        s_int = pow(m_int, d, n)
        # Converte a assinatura inteira de volta para bytes
        s_bytes = s_int.to_bytes((n.bit_length() + 7) // 8, 'big')
        
        # Retorna a assinatura em formato Base64 (string)
        return base64.b64encode(s_bytes).decode(), ""

    def pss_verify(self, message: str, signature_b64: str, public_key: Tuple[int, int]) -> bool:
        """
        Verifica uma assinatura RSA-PSS.
        'message': A mensagem original (string).
        'signature_b64': A assinatura em formato Base64 (string).
        'public_key': A chave pública RSA (e, n).
        Retorna: True se a assinatura for válida, False caso contrário.
        """
        e, n = public_key
        try:
            # Decodifica a assinatura de Base64 para bytes e depois para inteiro
            s_bytes = base64.b64decode(signature_b64)
            s_int = int.from_bytes(s_bytes, 'big')
            
            # Verifica se o valor da assinatura é menor que o módulo 'n'
            if s_int >= n:
                return False
            
            # Operação de verificação RSA (elevação à potência 'e' modulo 'n')
            m_int = pow(s_int, e, n)
            
            # Converte o resultado de volta para o bloco codificado (EM)
            em_bits = n.bit_length() - 1
            em_len = (em_bits + 7) // 8
            EM = m_int.to_bytes(em_len, 'big')
            
            # Realiza a verificação EMSA-PSS
            return self.emsa_pss_verify(message.encode('utf-8'), EM, em_bits)
        except Exception as e:
            # Qualquer erro durante o processo de decodificação/verificação indica uma assinatura inválida
            print(f"Erro durante a verificação: {e}")
            return False

