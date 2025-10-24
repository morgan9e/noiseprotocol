from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519, x448, ec

from noise.exceptions import NoiseValueError
from noise.functions.keypair import KeyPair


class KeyPair25519(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 32:
            raise NoiseValueError('Invalid length of private_bytes! Should be 32')
        private = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key()
        return cls(private=private, public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 32:
            raise NoiseValueError('Invalid length of public_bytes! Should be 32')
        public = x25519.X25519PublicKey.from_public_bytes(public_bytes)
        return cls(public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))


class KeyPair448(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 56:
            raise NoiseValueError('Invalid length of private_bytes! Should be 56')
        private = x448.X448PrivateKey.from_private_bytes(private_bytes)
        public = private.public_key()
        return cls(private=private, public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 56:
            raise NoiseValueError('Invalid length of private_bytes! Should be 56')
        public = x448.X448PublicKey.from_public_bytes(public_bytes)
        return cls(public=public, public_bytes=public.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw))


class KeyPairSecp256r1(KeyPair):
    @classmethod
    def from_private_bytes(cls, private_bytes):
        if len(private_bytes) != 32:
            raise NoiseValueError('Invalid length of private_bytes! Should be 32')
        private_int = int.from_bytes(private_bytes, byteorder='big')
        try:
            private = ec.derive_private_key(private_int, ec.SECP256R1())
        except ValueError as exc:
            raise NoiseValueError('Invalid secp256r1 private key scalar') from exc
        public = private.public_key()
        public_bytes = public.public_bytes(encoding=serialization.Encoding.X962,
                                           format=serialization.PublicFormat.UncompressedPoint)
        return cls(private=private, public=public, public_bytes=public_bytes)

    @classmethod
    def from_public_bytes(cls, public_bytes):
        if len(public_bytes) != 65:
            raise NoiseValueError('Invalid length of public_bytes! Should be 65')
        try:
            public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_bytes)
        except ValueError as exc:
            raise NoiseValueError('Invalid secp256r1 public key bytes') from exc
        public_bytes = public.public_bytes(encoding=serialization.Encoding.X962,
                                           format=serialization.PublicFormat.UncompressedPoint)
        return cls(public=public, public_bytes=public_bytes)
