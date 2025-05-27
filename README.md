# Sistema di Comunicazione Sicura con ECDH, AES e ECDSA

Questo progetto implementa una demo di un sistema di comunicazione sicura tra due parti (Alice e Bob) utilizzando algoritmi crittografici fondamentali:  
- **ECDH** (Elliptic Curve Diffie-Hellman) per lo scambio sicuro di chiavi  
- **AES** (Advanced Encryption Standard) per la cifratura simmetrica dei messaggi  
- **ECDSA** (Elliptic Curve Digital Signature Algorithm) per la firma digitale e verifica di autenticità  

---

## Funzionamento

1. **Generazione chiavi ECC:**  
   Alice e Bob generano ciascuno una coppia di chiavi private e pubbliche usando la curva ellittica SECP256R1.

2. **Scambio e derivazione della chiave condivisa:**  
   Attraverso l’algoritmo ECDH, Alice e Bob combinano la loro chiave privata con la chiave pubblica dell’altro per ottenere un segreto condiviso identico.  
   Per aumentare la sicurezza, da questo segreto condiviso viene derivata una chiave AES a 256 bit utilizzando una funzione di derivazione chiave (PBKDF2 con SHA-256 e salt casuale).

3. **Cifratura del messaggio:**  
   Il messaggio da inviare viene cifrato con AES in modalità CBC, usando la chiave simmetrica derivata e un vettore di inizializzazione (IV) casuale.

4. **Firma digitale:**  
   Alice firma il messaggio originale con la sua chiave privata utilizzando ECDSA e SHA-256, generando una firma che garantisce autenticità e integrità.

5. **Decifratura e verifica:**  
   Bob riceve il messaggio cifrato, lo decifra con la chiave AES derivata. Successivamente, verifica la firma digitale con la chiave pubblica di Alice per assicurarsi che il messaggio non sia stato alterato e provenga realmente da Alice.

---

## Come usare

1. Esegui lo script Python.  
2. Quando richiesto, inserisci il messaggio che vuoi inviare da Alice a Bob.  
3. Il programma mostrerà i dettagli di ogni passaggio (generazione chiavi, derivazione chiave AES, cifratura, firma, decifratura e verifica).  
4. Alla fine, vedrai il messaggio decifrato da Bob e il risultato della verifica della firma digitale.

---

## Requisiti

- Python 3.6+  
- Libreria `cryptography` (installabile con `pip install cryptography`)

---

## Note tecniche

- La sicurezza dello scambio di chiavi si basa sulla difficoltà computazionale del problema del logaritmo discreto su curve ellittiche.  
- L’uso di un salt casuale nel KDF protegge da attacchi di precomputazione (rainbow table).  
- La firma digitale ECDSA garantisce che il messaggio non sia stato modificato e conferma l’identità del mittente.  
- AES-CBC richiede la corretta gestione del padding e dell’IV; in questa demo l’IV è generato casualmente per ogni cifratura.

---

## Autori

Karim Acciaro Emanuele Dante

---


