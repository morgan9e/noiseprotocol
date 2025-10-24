from cryptography.hazmat.primitives.asymmetric import ec

from noise.connection import NoiseConnection, Keypair

class TestConnection(object):
    def do_test_connection(self, name):
        key = b"\x00" * 32
        left = NoiseConnection.from_name(name)
        left.set_psks(key)
        left.set_as_initiator()
        left.start_handshake()

        right = NoiseConnection.from_name(name)
        right.set_psks(key)
        right.set_as_responder()
        right.start_handshake()

        h = left.write_message()
        _ = right.read_message(h)
        h2 = right.write_message()
        left.read_message(h2)

        assert left.handshake_finished
        assert right.handshake_finished

        enc = left.encrypt(b"hello")
        dec = right.decrypt(enc)
        assert dec == b"hello"

    def test_25519(self):
        name = b"Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s"
        self.do_test_connection(name)

    def test_448(self):
        name = b"Noise_NNpsk0_448_ChaChaPoly_BLAKE2s"
        self.do_test_connection(name)

    def test_secp256r1_xxpsk3(self):
        name = b"Noise_XXpsk3_secp256r1_AESGCM_SHA256"
        psk = b"\x01" * 32

        left = NoiseConnection.from_name(name)
        left.set_psks(psk)
        left.set_as_initiator()
        left_static = ec.generate_private_key(ec.SECP256R1())
        left_private_bytes = left_static.private_numbers().private_value.to_bytes(32, "big")
        left.set_keypair_from_private_bytes(Keypair.STATIC, left_private_bytes)
        left.start_handshake()

        right = NoiseConnection.from_name(name)
        right.set_psks(psk)
        right.set_as_responder()
        right_static = ec.generate_private_key(ec.SECP256R1())
        right_private_bytes = right_static.private_numbers().private_value.to_bytes(32, "big")
        right.set_keypair_from_private_bytes(Keypair.STATIC, right_private_bytes)
        right.start_handshake()

        message1 = left.write_message()
        right.read_message(message1)

        message2 = right.write_message()
        left.read_message(message2)

        message3 = left.write_message()
        right.read_message(message3)

        assert left.handshake_finished
        assert right.handshake_finished

        ciphertext = left.encrypt(b"hello")
        plaintext = right.decrypt(ciphertext)
        assert plaintext == b"hello"
