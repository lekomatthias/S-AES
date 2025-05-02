from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from time import time
from base64 import b64encode, b64decode

# Decorador para medir tempo de execução
def timer(func):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = func(*args, **kwargs)
        end_time = time()
        timed = end_time - start_time
        print(f"Tempo de execução da função com modo {args[0].GetMode()}: {timed:.4f} segundos")
        return [result, timed]
    return wrapper


# classe feita com o auxílio do ilustríssimo chat GPT :)
class AES_Cipher:
    def __init__(self, mode):
        self.mode = mode
        self.key = None

    def GetMode(self):
        return self.mode

    def SetKey(self, key):
        self.key = key

    @timer
    def encrypt(self, plaintext):
        ''' Implementação dos modos de operação do AES separadamente'''
        # aqui cada modo precisou de uma implementação diferente
        # pois uns usam IV, outros nonce.
        if self.mode == 'ECB':
            cipher = AES.new(self.key, AES.MODE_ECB)
            padded = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded)
            return ciphertext

        elif self.mode == 'CBC':
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            padded = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded)
            return iv + ciphertext

        elif self.mode == 'CFB':
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            return iv + ciphertext

        elif self.mode == 'OFB':
            iv = get_random_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
            ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
            return iv + ciphertext

        elif self.mode == 'CTR':
            nonce = get_random_bytes(8)
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            ciphertext = cipher.encrypt(plaintext)
            return nonce + ciphertext

    @timer
    def decrypt(self, ciphertext):
        ''' Implementação dos modos de operação para decriptar '''
        if self.mode == 'ECB':
            cipher = AES.new(self.key, AES.MODE_ECB)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        elif self.mode == 'CBC':
            iv = ciphertext[:AES.block_size]
            ciphertext = ciphertext[AES.block_size:]
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        elif self.mode == 'CFB':
            iv = ciphertext[:AES.block_size]
            ciphertext = ciphertext[AES.block_size:]
            cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        elif self.mode == 'OFB':
            iv = ciphertext[:AES.block_size]
            ciphertext = ciphertext[AES.block_size:]
            cipher = AES.new(self.key, AES.MODE_OFB, iv=iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            
        elif self.mode == 'CTR':
            nonce = ciphertext[:8]
            ciphertext = ciphertext[8:]
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
        
        # retorno já decodificado para facilitar o print posterior
        return plaintext.decode()
    

if __name__ == "__main__":
    modes = ['ECB', 'CBC', 'CFB', 'OFB', 'CTR']
    key = b'1' * 16  # chave de 16 bytes
    # texto repetido para verificar a repetição de blocos +
    # texto grande para conseguir medir o tempo de execução
    plaintext = "texto para ser cifrado" * 1000000
    plaintext = plaintext.encode()

    # Não coloquei o texto cifrado em base64 pq fica muito grande e é
    # muito dufícil verificar a repetição visualmente.

    times = []
    repeated = []

    for mode in modes:
        aes = AES_Cipher(mode)
        aes.SetKey(key)

        # Criptografa
        ciphertext, et = aes.encrypt(plaintext)

        # Verifica repetição de blocos (tamanho de bloco AES = 16 bytes)
        block_size = 16
        # Divide o texto em blocos
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
        total_blocks = len(blocks)
        unique_blocks = len(set(blocks))
        # Verifica quantos blocos foram repetidos
        repeated_blocks = total_blocks - unique_blocks
        print(f"repetições: {repeated_blocks} de {total_blocks}")

        # Descriptografa e verifica se é igual ao original
        decrypted_text, dt = aes.decrypt(ciphertext)
        print(f"Texto recuperado corretamente? --> {'Sim' if decrypted_text == plaintext.decode() else 'Não'}")
        print('-' * 70)

        times.append([et, dt])
        repeated.append(repeated_blocks/total_blocks)

print("tabela de tempo e repetição:")
print("modo | tempo cifração | tempo decifração | repetições")
for mode in modes:
    print('-' * 53)
    print(f"{mode}  | {times[modes.index(mode)][0]:.4f} seg     | {times[modes.index(mode)][1]:.4f} seg       | {100*repeated[modes.index(mode)]:.0f}%")
print('-' * 53)
