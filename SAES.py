class SAES:
    '''Implementação didática do S-AES (Simplified AES)'''

    def __init__(self, debug=False):
        '''Inicializa o SAES com parâmetros básicos'''
        self.round_keys = []
        self.sbox = {
            0x0: 0x9,  0x1: 0x4,  0x2: 0xA,  0x3: 0xB,
            0x4: 0xD,  0x5: 0x1,  0x6: 0x8,  0x7: 0x5,
            0x8: 0x6,  0x9: 0x2,  0xA: 0x0,  0xB: 0x3,
            0xC: 0xC,  0xD: 0xE,  0xE: 0xF,  0xF: 0x7
        }
        self.inv_sbox = {v: k for k, v in self.sbox.items()}
        self.debug = debug

    def SetDebug(self, debug):
        self.debug = debug

    def _Int2State(self, val):
        '''Converte um inteiro de 16 bits em estado 2x2 de nibbles'''
        return [[(val >> 12) & 0xF, (val >> 8) & 0xF], [(val >> 4) & 0xF, val & 0xF]]

    def _State2Int(self, state):
        '''Converte o estado 2x2 de nibbles em um inteiro de 16 bits'''
        return (state[0][0] << 12) | (state[0][1] << 8) | (state[1][0] << 4) | state[1][1]

    def KeyExpansion(self, key16):
        '''Expande a chave de 16 bits para três subchaves de 16 bits'''
        def RotNib(byte):
            return ((byte & 0x0F) << 4) | ((byte & 0xF0) >> 4)
            
        def SubNib(byte):
            return (self.sbox[(byte >> 4) & 0xF] << 4) | self.sbox[byte & 0xF]
        
        RCON1 = 0x80
        RCON2 = 0x30
        
        w0 = (key16 >> 8) & 0xFF
        w1 = key16 & 0xFF
        w2 = w0 ^ RCON1 ^ SubNib(RotNib(w1))
        w3 = w2 ^ w1
        w4 = w2 ^ RCON2 ^ SubNib(RotNib(w3))
        w5 = w4 ^ w3
        k0 = (w0 << 8) | w1
        k1 = (w2 << 8) | w3
        k2 = (w4 << 8) | w5
        
        self.round_keys = [self._Int2State(k0), self._Int2State(k1), self._Int2State(k2)]
        if self.debug: 
            print(f"Chaves de rodada: {self.round_keys[0]}, {self.round_keys[1]}, {self.round_keys[2]}")
        return self.round_keys

    def AddRoundKey(self, state, key):
        '''Adiciona a chave de rodada ao estado usando XOR'''
        for i in range(2):
            for j in range(2):
                state[i][j] ^= key[i][j]
        if self.debug:
            print(f"AddRoundKey: \n|{state[0][0]:X}  {state[0][1]:X}|\n|{state[1][0]:X}  {state[1][1]:X}|")
        return state
    
    def SubNibbles(self, state):
        '''Substitui os nibbles do estado usando a S-Box'''
        for i in range(2):
            for j in range(2):
                state[i][j] = self.sbox[state[i][j]]
        if self.debug:
            print(f"SubNibbles: \n|{state[0][0]:X}  {state[0][1]:X}|\n|{state[1][0]:X}  {state[1][1]:X}|")
        return state
    
    def InvSubNibbles(self, state):
        '''Substitui os nibbles do estado usando a S-Box inversa'''
        for i in range(2):
            for j in range(2):
                state[i][j] = self.inv_sbox[state[i][j]]
        if self.debug:
            print(f"InvSubNibbles: \n|{state[0][0]:X}  {state[0][1]:X}|\n|{state[1][0]:X}  {state[1][1]:X}|")
        return state
    
    def ShiftRows(self, state):
        '''Desloca a segunda linha do estado (swap de nibbles)'''
        state[1][0], state[1][1] = state[1][1], state[1][0]
        if self.debug:
            print(f"ShiftRows: \n|{state[0][0]:X}  {state[0][1]:X}|\n|{state[1][0]:X}  {state[1][1]:X}|")
        return state
    
    def _gf4_mul(self, a, b):
        '''Multiplicação no campo GF(2^4)'''
        p = 0
        for _ in range(4):
            if b & 1:
                p ^= a
            carry = a & 0x8
            a <<= 1
            if carry:
                a ^= 0x13
            a &= 0xF
            b >>= 1
        return p
    
    def MixColumns(self, state):
        '''Mistura as colunas do estado'''
        new_state = [[0, 0], [0, 0]]
        new_state[0][0] = state[0][0] ^ self._gf4_mul(4, state[1][0])
        new_state[0][1] = state[0][1] ^ self._gf4_mul(4, state[1][1])
        new_state[1][0] = self._gf4_mul(4, state[0][0]) ^ state[1][0]
        new_state[1][1] = self._gf4_mul(4, state[0][1]) ^ state[1][1]
        if self.debug:
            print(f"MixColumns: \n|{new_state[0][0]:X}  {new_state[0][1]:X}|\n|{new_state[1][0]:X}  {new_state[1][1]:X}|")
        return new_state
    
    def InvMixColumns(self, state):
        '''Mistura inversa das colunas do estado'''
        new_state = [[0, 0], [0, 0]]
        new_state[0][0] = self._gf4_mul(9, state[0][0]) ^ self._gf4_mul(2, state[1][0])
        new_state[0][1] = self._gf4_mul(9, state[0][1]) ^ self._gf4_mul(2, state[1][1])
        new_state[1][0] = self._gf4_mul(2, state[0][0]) ^ self._gf4_mul(9, state[1][0])
        new_state[1][1] = self._gf4_mul(2, state[0][1]) ^ self._gf4_mul(9, state[1][1])
        if self.debug:
            print(f"InvMixColumns: \n|{new_state[0][0]:X}  {new_state[0][1]:X}|\n|{new_state[1][0]:X}  {new_state[1][1]:X}|")
        return new_state
    
    def _Str2bits(self, string):
        '''Converte uma string de 2 caracteres ASCII em um inteiro de 16 bits'''
        if len(string) > 2:
            print("O tamanho máximo do bloco é de 16 bits. Truncando nos dois primeiros caracteres...")
            string = string[:2]
        elif len(string) < 2:
            string += '\0' * (2-len(string))
        return (ord(string[0]) << 8) | ord(string[1])
    
    def Encrypt(self, plaintext, key):
        '''Criptografa o texto plano usando a chave fornecida'''
        self.KeyExpansion(key)
        state = self._Int2State(self._Str2bits(plaintext))
        # adição da primeira chave
        state = self.AddRoundKey(state, self.round_keys[0])
        # 2 rodadas
        for i in range(1, 3):
            state = self.SubNibbles(state)
            state = self.ShiftRows(state)
            if i==1: state = self.MixColumns(state)
            state = self.AddRoundKey(state, self.round_keys[i])
        
        return self._State2Int(state)
    
    def _Bits2Str(self, bits):
        '''Converte um inteiro de 16 bits em uma string de 2 caracteres ASCII'''
        return chr((bits >> 8) & 0xFF) + chr(bits & 0xFF)

    def Decrypt(self, ciphertext, key):
        '''Descriptografa o texto cifrado usando a chave fornecida'''
        self.KeyExpansion(key)
        state = self._Int2State(ciphertext)
        # 2 rodadas
        for i in range(2, 0, -1):
            state = self.AddRoundKey(state, self.round_keys[i])
            if i==1: state = self.InvMixColumns(state)
            state = self.ShiftRows(state)
            state = self.InvSubNibbles(state)
        # adição da última chave
        state = self.AddRoundKey(state, self.round_keys[0])
        
        return self._Bits2Str(self._State2Int(state))


if __name__ == "__main__":
    from base64 import b64encode, b64decode
    saes = SAES(debug=True)

    key = 0x1234
    plaintext = "ok"
    
    print(f"Plaintext: {plaintext}")
    ciphertext = saes.Encrypt(plaintext, key)
    print(f"Ciphertext (hex): {ciphertext:04X}")
    print(f"Ciphertext (base64): {b64encode(ciphertext.to_bytes(2, 'big'))}")
    decrypted = saes.Decrypt(ciphertext, key)
    print(f"Decrypted: {decrypted}")
    if plaintext == decrypted: print("Encriptação de decriptação feita com sucesso!")