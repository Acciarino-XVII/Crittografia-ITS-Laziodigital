from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
import os

# Generazione delle chiavi private di Alice e Bob
alice_private_key = ec.generate_private_key(ec.SECP256R1())
bob_private_key = ec.generate_private_key(ec.SECP256R1())

# Generazione delle chiavi pubbliche corrispondenti
alice_public_key = alice_private_key.public_key()
bob_public_key = bob_private_key.public_key()

# Scambio delle chiavi pubbliche tra Alice e Bob
# Alice calcola la chiave condivisa
alice_shared_key = alice_private_key.exchange(ec.ECDH(), bob_public_key)

# Bob calcola la chiave condivisa
bob_shared_key = bob_private_key.exchange(ec.ECDH(), alice_public_key)

# La chiave condivisa derivata (salvataggio in una variabile comune)
assert alice_shared_key == bob_shared_key  # La chiave condivisa è la stessa

# Per la cifratura AES, possiamo derivare una chiave simmetrica tramite KDF (Key Derivation Function)
# Eseguiamo il derivamento con PBKDF2
salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
shared_key = kdf.derive(alice_shared_key)
print("Chiave condivisa derivata per AES:", shared_key.hex())
