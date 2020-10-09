class PaddingMechanisms():
    subclasses = {}
    def __init__(self, BS):
        self.BS = BS

    @classmethod
    def register_subclass(cls, message_type):
        def decorator(subclass):
            cls.subclasses[message_type] = subclass
            return subclass
        return decorator
    
    @classmethod
    def create(cls, message_type, BS):
        if message_type not in cls.subclasses:
            raise ValueError('Currently not support Padding Mechanism, {}.'.format(message_type))
        return cls.subclasses[message_type](BS)

@PaddingMechanisms.register_subclass('ISO_7816_4')
class ISO_7816_4(PaddingMechanisms):
    def pad(self, padlen):
        return padlen * b'\x00'
    
    def unpad(self, pt):
        for i in range(len(pt) - 1, len(pt) - 1 - self.BS, -1):
            if pt[i : i + 1] == b'\x80':
                return pt[:i]
            elif pt[i : i + 1] != b'\x00':
                raise ValueError('Plaintext, {}, seems to be unvalid.'.format(pt))
        raise ValueError('Plaintext, {}, seems to be unvalid.'.format(pt))
    
    def end(self, padlen):
        return b'\x80'

@PaddingMechanisms.register_subclass('PKCS')
class PKCS(PaddingMechanisms):
    def pad(self, padlen):
        return padlen * bytes([padlen + 1])

    def unpad(self, pt):
        pass
    
    def end(self, padlen):
        return bytes([padlen + 1])