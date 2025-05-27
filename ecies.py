from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def derive_aes_key(shared_secret: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    return digest.finalize()  # 32 byte chiave AES-256

def encrypt_message(message: bytes, public_key) -> tuple:
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    ephemeral_public_key = ephemeral_private_key.public_key()

    shared_secret = ephemeral_private_key.exchange(ec.ECDH(), public_key)
    aes_key = derive_aes_key(shared_secret)

    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    return ciphertext, iv, ephemeral_pub_bytes

def decrypt_message(ciphertext: bytes, iv: bytes, ephemeral_pub_bytes: bytes, private_key) -> bytes:
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ephemeral_pub_bytes)

    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
    aes_key = derive_aes_key(shared_secret)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext

if __name__ == "__main__":
    # Genera coppia chiavi del destinatario (Bob)
    bob_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    bob_public_key = bob_private_key.public_key()

    msg = input("Inserisci messaggio da cifrare: ").encode()

    ct, iv, eph_pub = encrypt_message(msg, bob_public_key)
    print(f"Messaggio cifrato (hex): {ct.hex()}")

    pt = decrypt_message(ct, iv, eph_pub, bob_private_key)
    print(f"Messaggio decifrato: {pt.decode()}")
