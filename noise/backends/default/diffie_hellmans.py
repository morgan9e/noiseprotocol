from cryptography.hazmat.primitives.asymmetric import x25519, x448, ec
from cryptography.hazmat.primitives import serialization

from noise.backends.default.keypairs import KeyPair25519, KeyPair448, KeyPairSecp256r1
from noise.exceptions import NoiseValueError
from noise.functions.dh import DH


class ED25519(DH):
    @property
    def klass(self):
        return KeyPair25519

    @property
    def dhlen(self):
        return 32

    def generate_keypair(self) -> 'KeyPair':
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair25519(private_key, public_key,
                            public_key.public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw))

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, x25519.X25519PrivateKey) or not isinstance(public_key, x25519.X25519PublicKey):
            raise NoiseValueError('Invalid keys! Must be x25519.X25519PrivateKey and x25519.X25519PublicKey instances')
        return private_key.exchange(public_key)


class ED448(DH):
    @property
    def klass(self):
        return KeyPair448

    @property
    def dhlen(self):
        return 56

    def generate_keypair(self) -> 'KeyPair':
        private_key = x448.X448PrivateKey.generate()
        public_key = private_key.public_key()
        return KeyPair448(private_key, public_key,
                          public_key.public_bytes(serialization.Encoding.Raw,
                                                  serialization.PublicFormat.Raw))

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, x448.X448PrivateKey) or not isinstance(public_key, x448.X448PublicKey):
            raise NoiseValueError('Invalid keys! Must be x448.X448PrivateKey and x448.X448PublicKey instances')
        return private_key.exchange(public_key)


class SECP256R1(DH):
    @property
    def klass(self):
        return KeyPairSecp256r1

    @property
    def dhlen(self):
        return 65

    def generate_keypair(self) -> 'KeyPair':
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(serialization.Encoding.X962,
                                               serialization.PublicFormat.UncompressedPoint)
        return KeyPairSecp256r1(private_key, public_key, public_bytes)

    def dh(self, private_key, public_key) -> bytes:
        if not isinstance(private_key, ec.EllipticCurvePrivateKey) or not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise NoiseValueError('Invalid keys! Must be secp256r1 private and public key instances')
        if not isinstance(private_key.curve, ec.SECP256R1) or not isinstance(public_key.curve, ec.SECP256R1):
            raise NoiseValueError('Invalid curve for secp256r1 DH')
        return private_key.exchange(ec.ECDH(), public_key)
