import math
import hashlib
import base64
import random
import os 
from typing import Tuple
import time

"Implementa um sistema de assinatura digital RSA-PSS."
"Esta classe gera pares de chaves RSA e provê métodos para assinar e verificar mensagens."
class DigitalSignature:
    "Inicializa o sistema de assinatura digital com chaves RSA e parâmetros PSS."
    "Gera pares de chaves RSA para o bot e para um usuário."
    "Define funções de hash e comprimento do salt."
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.bot_public, self.bot_private = self.generate_keys() # Chaves RSA do bot
        self.user_public, self.user_private = self.generate_keys() # Chaves RSA de um usuário
        
        # Funções de hash para PSS (SHA3-256)
        self.hash_func = hashlib.sha3_256
        self.mgf_hash = hashlib.sha3_256 # Usado para MGF1
        self.salt_length = 32  # Tamanho do salt em bytes para PSS 

    # Funções auxiliares para geração de números primos e chaves RSA
    # Verifica se um número é primo usando o teste de Miller-Rabin.
    def is_prime(self, n: int, k: int = 20) -> bool:
        if n == 2:
            return True
        
        if n < 2 or n % 2 == 0:
            return False
        
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
            return True  

        # Repete k vezes com bases aleatórias
        for _ in range(k):
            if trial_composite(random.randrange(2, n-1)):
                return False
        return True

    "Gera um número primo de 'bits' de tamanho usando o teste de Miller-Rabin."
    def generate_prime(self, bits: int) -> int:
        while True:
            num = random.getrandbits(bits)
            # Garante que é ímpar e tem o bit mais significativo setado
            num |= (1 << (bits - 1)) | 1
            if self.is_prime(num):
                return num

    "Algoritmo de Euclides estendido para calcular o inverso modular."
    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return (b, 0, 1)
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        return (gcd, y1 - (b//a)*x1, x1)

    "Calcula o inverso modular de 'a' módulo 'm' usando o algoritmo de Euclides estendido."
    # Lança um erro se o inverso não existir (quando gcd(a, m) != 1).
    # Retorna o inverso modular de 'a' módulo 'm'.
    def mod_inverse(self, a: int, m: int) -> int:
        g, x, y = self.extended_gcd(a, m)
        if g != 1:
            raise ValueError("Modular inverse does not exist")
        return x % m

    "Gera um par de chaves RSA (pública e privada)."
    "Retorna uma tupla com a chave pública (e, n) e a chave privada (d, n)."
    def generate_keys(self, bits: int = None) -> Tuple[Tuple[int, int], Tuple[int, int]]:
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

    "Implementa a função MGF1 (Mask Generation Function) usada no PSS."
    "Gera uma máscara de bytes a partir de um seed e um comprimento desejado."
    def mgf1(self, seed: bytes, length: int) -> bytes:
        counter = 0
        output = b''
        hash_len = self.mgf_hash().digest_size 
        while len(output) < length:
            C = seed + counter.to_bytes(4, 'big')
            output += self.mgf_hash(C).digest()
            counter += 1
        return output[:length]

    "Codifica uma mensagem usando EMSA-PSS (Encoding Method for Signature Algorithm - PSS)."
    "Gera um salt aleatório internamente e prepara a mensagem para assinatura."
    def emsa_pss_encode(self, message: bytes, em_bits: int) -> bytes:

        h_len = self.hash_func().digest_size # Tamanho do hash (ex: 32 bytes para SHA3-256)
        s_len = self.salt_length # Comprimento do salt definido na inicialização
        em_len = (em_bits + 7) // 8 # Comprimento do bloco codificado em bytes

        if em_len < h_len + s_len + 2:
            raise ValueError("Encoding error: Output block too short")

        print(f"\n--- Processo de Codificação EMSA-PSS ---")
        print(f"Mensagem Original (para codificação): '{message.decode()}'")
        print(f"Tamanho do Bloco Codificado (EM) em bits: {em_bits}")

        # 1) H(M) = Hash da Mensagem
        hash_mensagem = self.hash_func(message).digest()
        print(f"  Hash da Mensagem (H(M)): {hash_mensagem.hex()}")
        
        # 2) Gera um salt aleatório (PADRÃO PSS: salt é gerado aqui)
        salt = os.urandom(s_len) # Usando os.urandom para criptografia forte
        print(f"  Salt Gerado: {salt.hex()}")

        # 3) M' = 0x00*8 || H(M) || salt
        # O prefixo de 8 bytes é usado para compatibilidade com PSS
        # O salt é adicionado após o hash da mensagem.
        M_linha = b'\x00' * 8 + hash_mensagem + salt
        print(f"  M' (8x00 || H(M) || Salt): {M_linha.hex()}")
        
        # 4) H = Hash(M')
        # O hash de M' é usado para gerar a máscara de dados.
        # Isso garante que a assinatura seja única para cada mensagem e salt.
        H = self.hash_func(M_linha).digest()
        print(f"  Hash de M' (H): {H.hex()}")

        # 5) DB = PS || 0x01 || salt
        # PS (Padding String) é uma string de bytes zero de comprimento suficiente
        PS = b'\x00' * (em_len - h_len - s_len - 2)
        bloco_dados = PS + b'\x01' + salt
        print(f"  Bloco de Dados (DB): {bloco_dados.hex()}")

        # 6) mascara_db = MGF1(H)
        # A máscara de dados é gerada a partir do hash H.
        # Isso garante que a máscara seja única para cada assinatura.
        mascara_db = self.mgf1(H, em_len - h_len - 1)
        print(f"  Máscara DB (MGF1(H)): {mascara_db.hex()}")

        # 7) bloco_mascarado = bloco_dados XOR mascara_db
        # A máscara é aplicada ao bloco de dados para criar o bloco mascarado.
        # Isso garante que o bloco mascarado seja único e não previsível.
        bloco_mascarado = bytes(b ^ m for b, m in zip(bloco_dados, mascara_db))
        print(f"  Bloco Mascarado (masked_db): {bloco_mascarado.hex()}")

        # 8) Ajuste de bits excedentes no primeiro byte
        # Se o comprimento do bloco mascarado exceder o tamanho efetivo, ajusta o primeiro byte.
        # Isso garante que o bloco mascarado tenha o tamanho correto.
        excesso = 8 * em_len - em_bits
        if excesso > 0:
            primeiro = bloco_mascarado[0] & (0xFF >> excesso)
            bloco_mascarado = bytes([primeiro]) + bloco_mascarado[1:]
            print(f"  Bloco Mascarado (após ajuste de bits): {bloco_mascarado.hex()}")

        # 9) EM = bloco_mascarado || H || 0xBC
        # O bloco mascarado é concatenado com o hash H e o byte de trailer 0xBC.
        # O byte 0xBC é usado para indicar o final do bloco codificado.
        bloco_codificado = bloco_mascarado + H + b'\xbc'
        print(f"  Bloco Codificado (EM): {bloco_codificado.hex()}")
        return bloco_codificado
    
    "Verifica uma assinatura usando EMSA-PSS."
    "Verifica se o bloco codificado (EM) corresponde à mensagem original."
    "O salt é extraído do bloco EM."
    def emsa_pss_verify(self, message: bytes, EM: bytes, em_bits: int) -> bool:

        m_hash = self.hash_func(message).digest()
        h_len = self.hash_func().digest_size
        s_len = self.salt_length
        em_len = (em_bits + 7) // 8
        
        print(f"  Hash da Mensagem Original (H(M) esperado): {m_hash.hex()}")
        print(f"  Tamanho do Bloco EM Esperado (bytes): {em_len}")

        if em_len < h_len + s_len + 2:
            print(f"  Verificação Falhou: EM muito curto.")
            return False
        if EM[-1:] != b'\xbc':
            print(f"  Verificação Falhou: Byte de trailer (0xBC) ausente ou incorreto.")
            return False
        
        masked_db = EM[:em_len - h_len - 1]
        H = EM[em_len - h_len - 1:-1]
        print(f"  H (extraído do EM): {H.hex()}")
        print(f"  Bloco Mascarado (masked_db extraído do EM): {masked_db.hex()}")
        
        if masked_db[0] >> (8 - (8 * em_len - em_bits)) != 0:
            print(f"  Verificação Falhou: Bits excedentes do masked_db não são zero.")
            return False
        
        # Regera a máscara de dados usando MGF1 com o hash H
        db_mask = self.mgf1(H, em_len - h_len - 1)
        print(f"  Máscara DB (MGF1(H) regerada): {db_mask.hex()}")
        
        # Reconstrói o bloco de dados (DB) usando a máscara
        DB = bytes([db_mask[i] ^ masked_db[i] for i in range(len(masked_db))])
        DB = bytes([DB[0] & (0xFF >> (8 * em_len - em_bits))]) + DB[1:]
        print(f"  Bloco de Dados (DB reconstruído): {DB.hex()}")
        
        # Verifica se o padding string (PS) e o byte 0x01 estão corretos
        PS_len = em_len - h_len - s_len - 2
        if DB[:PS_len] != b'\x00' * PS_len or DB[PS_len] != 0x01:
            print(f"  Verificação Falhou: Padding String (PS) ou byte 0x01 incorreto.")
            return False
        

        salt = DB[PS_len + 1:] # O salt é extraído aqui para verificação
        print(f"  Salt (extraído do DB reconstruído): {salt.hex()}")
        
        M_prime = b'\x00' * 8 + m_hash + salt
        print(f"  M' (8x00 || H(M) esperado || Salt extraído): {M_prime.hex()}")
        
        H_prime = self.hash_func(M_prime).digest()
        print(f"  H' (Hash de M' reconstruído): {H_prime.hex()}")
        
        comparison_result = (H == H_prime)
        print(f"  Comparação H == H': {comparison_result}")
        return comparison_result

    "Assina uma mensagem usando o esquema RSA-PSS."
    "Retorna a assinatura em Base64 e um salt vazio (não usado no PSS)."
    # O salt não é retornado separadamente, pois é embutido no PSS
    def pss_sign(self, message: str, private_key: Tuple[int, int]) -> Tuple[str, str]:
        d, n = private_key
        em_bits = n.bit_length() - 1 
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
        print(f"Assinatura Gerada (Base64): '{signature_b64[:30]}...' (completa: {signature_b64})") # Mostra apenas o início
        print(f"----------------------------")
        return signature_b64, ""

    "Verifica uma assinatura RSA-PSS."
    "Recebe a mensagem original, a assinatura em Base64 e a chave pública."
    "Retorna True se a assinatura for válida, False caso contrário."
    # A assinatura é verificada usando o esquema PSS, que inclui a verificação do bloco codificado
    # A assinatura é decodificada de Base64 para bytes e convertida para inteiro
        # A verificação é feita comparando o bloco codificado reconstruído com o original
    def pss_verify(self, message: str, signature_b64: str, public_key: Tuple[int, int]) -> bool:

        e, n = public_key
        
        print(f"\n--- Processo de Verificação ---")
        print(f"Mensagem Recebida (para verificação): '{message}'")
        print(f"Assinatura Recebida (Base64): '{signature_b64[:30]}...' (completa: {signature_b64})") # Mostra apenas o início
        
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
            print(f"  Bloco Codificado (EM) recuperado da assinatura: {EM.hex()}")
            
            # Realiza a verificação EMSA-PSS
            is_valid = self.emsa_pss_verify(message.encode('utf-8'), EM, em_bits)
            
            print(f"Resultado da Verificação: {'VÁLIDA' if is_valid else 'INVÁLIDA'}")
            print(f"----------------------------")
            return is_valid
        except Exception as e:
            print(f"Resultado da Verificação: INVÁLIDA (Erro: {e})")
            print(f"----------------------------")
            return False

