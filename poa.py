from pwn import *
from paddingmechanisms import PaddingMechanisms

class POA():
    def __init__(self, host: str, port: int, BS: int, endStr: bytes, paddingErrorStr: bytes, paddingMechanism):
        self.PM = PaddingMechanisms.create(paddingMechanism, BS)
        self.host = host
        self.port = port
        self.BS = BS
        self.endStr = endStr
        self.paddingErrorStr = paddingErrorStr
        self.plaintext = b''

    def solve(self):
        self.r = remote(self.host, self.port)
        self.r.recvuntil(self.endStr)
        cipherHEX = self.r.recvline()[:-1]
        self.cipher = bytes.fromhex(cipherHEX.decode())
        self.cipherList = [ self.cipher[ i : i+self.BS] for i in range(0, len(self.cipher), self.BS) ]
        return self.__derivePT()

    def __derivePT(self):
        for i in range(1, len(self.cipherList)):
            self.plaintext += self.__PaddingOracleAttack(i)
        return self.PM.unpad(self.plaintext)
    
    def __PaddingOracleAttack(self, blockIdx):
        intermediate = b'\x00' * self.BS
        for i in range(self.BS):
            for j in range(256):
                tmp = self.PM.pad(i)
                mod = self.cipher[ : BS * (blockIdx - 1)] + intermediate[ : (self.BS - 1 - i) ] + bytes([j]) + self.__xor(intermediate[ (self.BS - i) : ], tmp) + self.cipherList[blockIdx]
                modHEX = mod.hex()
                self.r.sendline(modHEX)
                stat = self.r.recvline()
                self.r.recvuntil(self.endStr)
                if self.paddingErrorStr not in stat:
                    intermediate = intermediate[ : (self.BS - 1 - i) ] + self.__xor(bytes([j]), self.PM.end(i)) + intermediate[ (self.BS - i): ]
                    break
        return self.__xor(self.cipherList[blockIdx - 1], intermediate)

    def __xor(self, a, b):
        return bytes(i ^ j for i, j in zip(a, b))

if __name__ == '__main__':
    host = '140.112.31.97'
    port = 30000
    BS = 16
    p = POA(host, port, BS, b' = ', b'NOOOOOOOOO', 'ISO_7816_4')
    pt = p.solve()
    print (pt)