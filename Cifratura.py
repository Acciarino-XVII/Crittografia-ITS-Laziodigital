from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import os

#logo

art = r"""
 ________  ________  ________   _________  _______   ________      ________  ________  ________  ___  ________  ________  ________          ________  _______   ________  ___  ___  ________  ___  _________    ___    ___ 
|\   ___ \|\   __  \|\   ___  \|\___   ___\\  ___ \ |\   __  \    |\   __  \|\   ____\|\   ____\|\  \|\   __  \|\   __  \|\   __  \        |\   ____\|\  ___ \ |\   ____\|\  \|\  \|\   __  \|\  \|\___   ___\ |\  \  /  /|
\ \  \_|\ \ \  \|\  \ \  \\ \  \|___ \  \_\ \   __/|\ \  \|\  \  /\ \  \|\  \ \  \___|\ \  \___|\ \  \ \  \|\  \ \  \|\  \ \  \|\  \       \ \  \___|\ \   __/|\ \  \___|\ \  \\\  \ \  \|\  \ \  \|___ \  \_| \ \  \/  / /
 \ \  \ \\ \ \   __  \ \  \\ \  \   \ \  \ \ \  \_|/_\ \__     \/  \ \   __  \ \  \    \ \  \    \ \  \ \   __  \ \   _  _\ \  \\\  \       \ \_____  \ \  \_|/_\ \  \    \ \  \\\  \ \   _  _\ \  \   \ \  \   \ \    / / 
  \ \  \_\\ \ \  \ \  \ \  \\ \  \   \ \  \ \ \  \_|\ \|_/  __     /\ \  \ \  \ \  \____\ \  \____\ \  \ \  \ \  \ \  \\  \\ \  \\\  \       \|____|\  \ \  \_|\ \ \  \____\ \  \\\  \ \  \\  \\ \  \   \ \  \   \/  /  /  
   \ \_______\ \__\ \__\ \__\\ \__\   \ \__\ \ \_______\/  /_|\   / /\ \__\ \__\ \_______\ \_______\ \__\ \__\ \__\ \__\\ _\\ \_______\        ____\_\  \ \_______\ \_______\ \_______\ \__\\ _\\ \__\   \ \__\__/  / /    
    \|_______|\|__|\|__|\|__| \|__|    \|__|  \|_______/_______   \/  \|__|\|__|\|_______|\|_______|\|__|\|__|\|__|\|__|\|__|\|_______|       |\_________\|_______|\|_______|\|_______|\|__|\|__|\|__|    \|__|\___/ /     
                                                       |_______|\__\                                                                          \|_________|                                                    \|___|/      
                                                               \|__|                                                                                                                                                       
                                                                                                                                                                                                                           
    """
print(art)



def derive_aes_key(shared_secret: bytes, salt: bytes) -> bytes:
    print("[*] Derivazione chiave AES dalla chiave condivisa con PBKDF2 e salt...")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(shared_secret)

def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    print("[*] Cifratura del messaggio con AES-CBC...")
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    print(f"    -> IV generato (hex): {iv.hex()}")
    return ciphertext, iv

def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    print("[*] Decifratura del messaggio con AES-CBC...")
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext

def sign_message(private_key, message: bytes) -> bytes:
    print("[*] Firma digitale del messaggio con ECDSA (SHA-256)...")
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    print(f"    -> Firma generata (hex): {signature.hex()[:60]}...")  # Mostra solo un pezzo
    return signature

def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    print("[*] Verifica della firma digitale...")
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        print("    -> Firma valida!")
        return True
    except InvalidSignature:
        print("    -> Firma NON valida!")
        return False

# --- Simulazione Alice e Bob ---

print("[*] Generazione coppie di chiavi ECC per Alice e Bob...")
alice_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
alice_public_key = alice_private_key.public_key()

bob_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
bob_public_key = bob_private_key.public_key()

print("[*] Scambio chiavi pubbliche e calcolo chiave condivisa tramite ECDH...")
alice_shared_secret = alice_private_key.exchange(ec.ECDH(), bob_public_key)
bob_shared_secret = bob_private_key.exchange(ec.ECDH(), alice_public_key)
assert alice_shared_secret == bob_shared_secret
print("    -> La chiave condivisa è identica per entrambi.")

salt = os.urandom(16)
print(f"[*] Generazione salt casuale per PBKDF2 (hex): {salt.hex()}")

aes_key_alice = derive_aes_key(alice_shared_secret, salt)
aes_key_bob = derive_aes_key(bob_shared_secret, salt)

print(f"[*] Chiave AES derivata (hex): {aes_key_alice.hex()}")

message = input("\nInserisci il messaggio da cifrare: ").encode('utf-8')

signature = sign_message(alice_private_key, message)

ciphertext, iv = aes_encrypt(aes_key_alice, message)

print(f"\n[*] Messaggio cifrato (hex): {ciphertext.hex()}")

decrypted_message = aes_decrypt(aes_key_bob, ciphertext, iv)
print(f"\n[*] Messaggio decifrato da Bob: {decrypted_message.decode('utf-8')}")

if verify_signature(alice_public_key, decrypted_message, signature):
    print("\n[OK] Firma digitale verificata: il messaggio è autentico.")
else:
    print("\n[ERRORE] Firma digitale NON valida: il messaggio potrebbe essere stato alterato.")
