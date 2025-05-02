from SAES import SAES

class SAES(SAES):

    def _BlockPrepare(self, text, hex=False):
        blocks = []
        if hex: hex = 4
        else: hex = 2
        while len(text) > 0:
            if len(text) > hex:
                blocks.append(text[:hex])
                text = text[hex:]
            else:
                blocks.append(text)
                text = ''
        if self.debug: print(f"Blocks: {blocks}")
        return blocks
    
    def _BlockEncrypt2Hex(self, cipherblocks):
        '''Converte os blocos cifrados para string'''
        ciphertext = ''
        for i in range(len(cipherblocks)):
            ciphertext += f"{cipherblocks[i]:04X}"
        return ciphertext

    def EncriptText(self, plaintext, key):
        '''Criptografa o texto em claro usando o modo ECB'''
        blocks = self._BlockPrepare(plaintext)
        encripted_blocks = []
        for i in range(len(blocks)):
            encripted_blocks.append(self.Encrypt(blocks[i], key))
        return self._BlockEncrypt2Hex(encripted_blocks)
    
    def DecryptText(self, ciphertext, key):
        '''Descriptografa o texto cifrado usando o modo ECB'''
        blocks = self._BlockPrepare(ciphertext, hex=True)
        decrypted_blocks = []
        for i in range(len(blocks)):
            decrypted_blocks.append(self.Decrypt(int(blocks[i], 16), key))
        return ''.join(decrypted_blocks)

if __name__ == "__main__":
    from base64 import b64encode, b64decode
    saes = SAES()

    key = 0x1234
    plaintext = "texto mais longo longo"
    '''Escolhi esse testo exclusivamente pq posso ver " longo" em hexa repetindo. (vira: 4942 D7A8 708A)'''
    
    print(f"Plaintext: {plaintext}")
    ciphertext = saes.EncriptText(plaintext, key)
    print(f"Ciphertext (hex): {ciphertext}")
    # visualização em base64
    print(f"Ciphertext (base64): {b64encode(bytes.fromhex(ciphertext))}")
    print(f"Decrypted: {saes.DecryptText(ciphertext, key)}")