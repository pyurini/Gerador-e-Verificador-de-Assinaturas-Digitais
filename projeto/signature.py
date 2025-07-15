import math
import hashlib
import base64
import random
import os # Importado para os.urandom, usado na geração segura de salt para PSS
from typing import Tuple

class DigitalSignature:
    """
    Implementa um sistema de assinatura digital RSA-PSS.
    Gera pares de chaves RSA e provê métodos para assinar e verificar mensagens.
    """
    def __init__(self, key_size=2048):
        """
        Inicializa o sistema de assinatura.
        Gera pares de chaves RSA para o bot e para um usuário de exemplo.
        Define funções de hash e comprimento do salt.
        """
        self.key_size = key_size
        self.bot_public, self.bot_private = self.generate_keys() # Chaves RSA do bot
        self.user_public, self.user_private = self.generate_keys() # Chaves RSA de um usuário de exemplo
        
        # Funções de hash para PSS (SHA3-256 é uma boa escolha moderna)
        self.hash_func = hashlib.sha3_256
        self.mgf_hash = hashlib.sha3_256 # Usado para MGF1
        self.salt_length = 32  # Tamanho do salt em bytes para PSS (tamanho do hash digest)

    # --- Funções Auxiliares RSA (geração de chaves, inverso modular, etc.) ---
    def is_prime(self, n: int, k: int = 20) -> bool:
        """Teste probabilístico de Miller-Rabin para verificar se n é provável primo."""
        if n == 2:
            return True
        if n < 2 or n % 2 == 0:
            return False
        # Testes iniciais simples para otimização
        small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
        for p in small_primes:
            if n == p:
                return True
            if n % p == 0:
                return False

        # Escreve n-1 como 2^r * d
        r, d = 0, n - 1
        while d % 2 == 0:
            d //= 2
            r += 1

        # Função de teste witness
        def trial_composite(a) -> bool:
            x = pow(a, d, n)
            if x in (1, n-1): return False
            for _ in range(r-1):
                x = pow(x, 2, n)
                if x == n-1: return False
            return True  # composto

        # Repete k vezes com bases aleatórias
        for _ in range(k):
            if trial_composite(random.randrange(2, n-1)):
                return False
        return True

    def generate_prime(self, bits: int) -> int:
        """Gera um primo de 'bits' de tamanho usando Miller-Rabin."""
        while True:
            num = random.getrandbits(bits)
            # Garante que é ímpar e tem o bit mais significativo setado
            num |= (1 << (bits - 1)) | 1
            if self.is_prime(num):
                return num

    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """Algoritmo de Euclides estendido."""
        if a == 0:
            return (b, 0, 1)
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        return (gcd, y1 - (b//a)*x1, x1)

    def mod_inverse(self, a: int, m: int) -> int:
        """Calcula o inverso modular de 'a' módulo 'm' (usando Euclides estendido)."""
        g, x, y = self.extended_gcd(a, m)
        if g != 1:
            raise ValueError("Modular inverse does not exist")
        return x % m

    def generate_keys(self, bits: int = None) -> Tuple[Tuple[int, int], Tuple[int, int]]:
        """Gera par de chaves RSA (pública e privada)."""
        bits = bits or self.key_size
        p = self.generate_prime(bits // 2)
        q = self.generate_prime(bits // 2)
        while p == q: q = self.generate_prime(bits // 2) # Garante p e q diferentes
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537 # Expoente público comum
        while math.gcd(e, phi) != 1: # Garante que e e phi são coprimos
            p = self.generate_prime(bits // 2)
            q = self.generate_prime(bits // 2)
            n = p * q
            phi = (p - 1) * (q - 1)
        d = self.mod_inverse(e, phi)
        return (e, n), (d, n)

    # --- Funções PSS (Assinatura e Verificação) ---
    def mgf1(self, seed: bytes, length: int) -> bytes:
        """MGF1 (Mask Generation Function) usando self.mgf_hash."""
        counter = 0
        output = b''
        hash_len = self.mgf_hash().digest_size # Tamanho do digest da função de hash
        while len(output) < length:
            C = seed + counter.to_bytes(4, 'big')
            output += self.mgf_hash(C).digest()
            counter += 1
        return output[:length]

    def emsa_pss_encode(self, message: bytes, em_bits: int) -> bytes:
        """
        Codificação EMSA-PSS. Gera o salt internamente.
        Prepara a mensagem para ser assinada com RSA.
        """
        h_len = self.hash_func().digest_size # Tamanho do hash (ex: 32 bytes para SHA3-256)
        s_len = self.salt_length # Comprimento do salt definido na inicialização
        em_len = (em_bits + 7) // 8 # Comprimento do bloco codificado em bytes

        if em_len < h_len + s_len + 2:
            raise ValueError("Encoding error: Output block too short")

        # 1) H(M)
        hash_mensagem = self.hash_func(message).digest()
        
        # 2) Gera um salt aleatório (PADRÃO PSS: salt é gerado aqui)
        salt = os.urandom(s_len) # Usando os.urandom para criptografia forte

        # 3) M' = 0x00*8 || H(M) || salt
        M_linha = b'\x00' * 8 + hash_mensagem + salt
        
        # 4) H = Hash(M')
        H = self.hash_func(M_linha).digest()

        # 5) DB = PS || 0x01 || salt
        PS = b'\x00' * (em_len - h_len - s_len - 2)
        bloco_dados = PS + b'\x01' + salt

        # 6) mascara_db = MGF1(H)
        mascara_db = self.mgf1(H, em_len - h_len - 1)

        # 7) bloco_mascarado = bloco_dados XOR mascara_db
        bloco_mascarado = bytes(b ^ m for b, m in zip(bloco_dados, mascara_db))

        # 8) Ajuste de bits excedentes no primeiro byte
        excesso = 8 * em_len - em_bits
        if excesso > 0:
            primeiro = bloco_mascarado[0] & (0xFF >> excesso)
            bloco_mascarado = bytes([primeiro]) + bloco_mascarado[1:]

        # 9) EM = bloco_mascarado || H || 0xBC
        bloco_codificado = bloco_mascarado + H + b'\xbc'
        return bloco_codificado

    def emsa_pss_verify(self, message: bytes, EM: bytes, em_bits: int) -> bool:
        """
        Verificação EMSA-PSS.
        Verifica se um bloco codificado (EM) corresponde à mensagem original.
        O salt é extraído do bloco EM.
        """
        m_hash = self.hash_func(message).digest()
        h_len = self.hash_func().digest_size
        s_len = self.salt_length
        em_len = (em_bits + 7) // 8
        
        if em_len < h_len + s_len + 2:
            return False
        if EM[-1:] != b'\xbc':
            return False
        
        masked_db = EM[:em_len - h_len - 1]
        H = EM[em_len - h_len - 1:-1]
        
        if masked_db[0] >> (8 - (8 * em_len - em_bits)) != 0:
            return False
        
        db_mask = self.mgf1(H, em_len - h_len - 1)
        
        DB = bytes([db_mask[i] ^ masked_db[i] for i in range(len(masked_db))])
        DB = bytes([DB[0] & (0xFF >> (8 * em_len - em_bits))]) + DB[1:]
        
        PS_len = em_len - h_len - s_len - 2
        if DB[:PS_len] != b'\x00' * PS_len or DB[PS_len] != 0x01:
            return False
        
        salt = DB[PS_len + 1:] # O salt é extraído aqui para verificação
        
        M_prime = b'\x00' * 8 + m_hash + salt
        H_prime = self.hash_func(M_prime).digest()
        
        return H == H_prime # Compara os hashes

    def pss_sign(self, message: str, private_key: Tuple[int, int]) -> Tuple[str, str]:
        """
        Assina uma mensagem usando o esquema RSA-PSS.
        Retorna: Uma tupla (assinatura_em_base64, salt_em_base64_vazio).
                 O salt não é retornado separadamente, pois é embutido no PSS.
        """
        d, n = private_key
        em_bits = n.bit_length() - 1 # Tamanho efetivo do módulo em bits
        message_bytes = message.encode('utf-8') # Codifica a mensagem para bytes
        
        print(f"\n--- Processo de Assinatura ---")
        print(f"Mensagem Original (para assinatura): '{message}'")
        
        # Codificação EMSA-PSS para preparar a mensagem para a operação RSA
        EM = self.emsa_pss_encode(message_bytes, em_bits)
        m_int = int.from_bytes(EM, 'big') # Converte o bloco codificado para inteiro
        
        # Operação de assinatura RSA (elevação à potência 'd' modulo 'n')
        s_int = pow(m_int, d, n)
        # Converte a assinatura inteira de volta para bytes
        s_bytes = s_int.to_bytes((n.bit_length() + 7) // 8, 'big')
        
        # Retorna a assinatura em formato Base64 (string)
        signature_b64 = base64.b64encode(s_bytes).decode()
        print(f"Assinatura Gerada (Base64): '{signature_b64[:30]}...'") # Mostra apenas o início
        print(f"----------------------------")
        return signature_b64, ""

    def pss_verify(self, message: str, signature_b64: str, public_key: Tuple[int, int]) -> bool:
        """
        Verifica uma assinatura RSA-PSS.
        Retorna: True se a assinatura for válida, False caso contrário.
        """
        e, n = public_key
        
        print(f"\n--- Processo de Verificação ---")
        print(f"Mensagem Recebida (para verificação): '{message}'")
        print(f"Assinatura Recebida (Base64): '{signature_b64[:30]}...'") # Mostra apenas o início
        
        try:
            # Decodifica a assinatura de Base64 para bytes e depois para inteiro
            s_bytes = base64.b64decode(signature_b64)
            s_int = int.from_bytes(s_bytes, 'big')
            
            # Verifica se o valor da assinatura é menor que o módulo 'n'
            if s_int >= n:
                print(f"Resultado da Verificação: INVÁLIDA (Assinatura maior que o módulo n)")
                print(f"----------------------------")
                return False
            
            # Operação de verificação RSA (elevação à potência 'e' modulo 'n')
            m_int = pow(s_int, e, n)
            
            # Converte o resultado de volta para o bloco codificado (EM)
            em_bits = n.bit_length() - 1
            em_len = (em_bits + 7) // 8
            EM = m_int.to_bytes(em_len, 'big')
            
            # Realiza a verificação EMSA-PSS
            is_valid = self.emsa_pss_verify(message.encode('utf-8'), EM, em_bits)
            
            print(f"Resultado da Verificação: {'VÁLIDA' if is_valid else 'INVÁLIDA'}")
            print(f"----------------------------")
            return is_valid
        except Exception as e:
            # Qualquer erro durante o processo de decodificação/verificação indica uma assinatura inválida
            print(f"Resultado da Verificação: INVÁLIDA (Erro: {e})")
            print(f"----------------------------")
            return False

