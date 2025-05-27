from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def derive_aes_key(shared_secret: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    return digest.finalize()

def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext, iv

def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

# Simulazione Alice e Bob

# 1. Generano coppie di chiavi ECC
alice_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
alice_public_key = alice_private_key.public_key()

bob_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
bob_public_key = bob_private_key.public_key()

# 2. Alice calcola segreto condiviso usando sua privata e chiave pubblica di Bob
shared_secret_alice = alice_private_key.exchange(ec.ECDH(), bob_public_key)
aes_key_alice = derive_aes_key(shared_secret_alice)

# 3. Bob calcola segreto condiviso usando sua privata e chiave pubblica di Alice
shared_secret_bob = bob_private_key.exchange(ec.ECDH(), alice_public_key)
aes_key_bob = derive_aes_key(shared_secret_bob)

# Ora aes_key_alice == aes_key_bob

# 4. Alice cifra un messaggio
# ...

message = input("Inserisci il messaggio da cifrare: ").encode('utf-8')

ciphertext, iv = aes_encrypt(aes_key_alice, message)
print("Messaggio cifrato (hex):", ciphertext.hex())

decrypted_message = aes_decrypt(aes_key_bob, ciphertext, iv)
print("Messaggio decifrato:", decrypted_message.decode('utf-8'))

# message = b"Ciao Bob, questo è un messaggio segreto!"
# ciphertext, iv = aes_encrypt(aes_key_alice, message)
# print("Messaggio cifrato (hex):", ciphertext.hex())

# 5. Bob decifra il messaggio
decrypted_message = aes_decrypt(aes_key_bob, ciphertext, iv)
print("Messaggio decifrato:", decrypted_message.decode())
