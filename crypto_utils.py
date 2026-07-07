"""
crypto_utils.py
================
Cryptographic utility module for the E2EE Chat System.

Role in the system:
  - Generates RSA-2048 key pairs for each client session.
  - Encrypts/decrypts AES session keys using RSA with OAEP padding.
  - Encrypts/decrypts messages using AES-128 in CBC mode with PKCS7 padding.
  - Provides helper functions for base64 encoding/decoding of binary data.

Subject: Data Encryption and Network Security
Concepts: RSA-2048, AES-128-CBC, Hybrid Encryption, OAEP Padding, PKCS7 Padding, IV
"""

import base64

# RSA key generation and public-key operations
from Crypto.PublicKey import RSA

# AES cipher for symmetric message encryption
from Crypto.Cipher import AES

# PKCS1_OAEP — Optimal Asymmetric Encryption Padding for RSA
# OAEP is semantically secure; prevents several classical RSA attacks
from Crypto.Cipher import PKCS1_OAEP

# PKCS7 padding: ensures plaintext length is a multiple of AES block size (16 bytes)
from Crypto.Util.Padding import pad, unpad

# Cryptographically secure random byte generator
from Crypto.Random import get_random_bytes


# ─────────────────────────────────────────────────────────────────────────────
# RSA Key Pair Generation
# ─────────────────────────────────────────────────────────────────────────────


def generate_rsa_keypair():
    """
    Generate a fresh 2048-bit RSA key pair for a client session.

    RSA provides ASYMMETRIC cryptography:
      - The PUBLIC KEY is shared openly with other clients (via the server).
      - The PRIVATE KEY is kept secret and never leaves the client.

    Key Size: 2048 bits is the current minimum recommended by NIST for RSA.
    Larger key sizes (4096 bits) are more secure but slower.

    Returns:
        tuple: (private_key_pem: str, public_key_pem: str)
               Both keys are PEM-encoded strings for easy serialization.
    """
    # RSA provides asymmetric encryption for key exchange
    key = RSA.generate(2048)

    # Export the full key object as PEM (includes both private and public parts)
    private_key_pem = key.export_key().decode("utf-8")

    # Export only the public component — this is safe to send to others
    public_key_pem = key.publickey().export_key().decode("utf-8")

    return private_key_pem, public_key_pem


# ─────────────────────────────────────────────────────────────────────────────
# Hybrid Encryption: RSA-encrypt an AES Key
# ─────────────────────────────────────────────────────────────────────────────


def encrypt_aes_key_with_rsa(aes_key: bytes, recipient_public_key_pem: str) -> bytes:
    """
    Encrypt a raw AES session key using the recipient's RSA public key.

    This is the KEY EXCHANGE step in hybrid encryption:
      - Hybrid encryption: RSA for key exchange, AES for data encryption.
      - RSA is used ONLY to protect the small AES key (16 bytes).
      - AES is then used to encrypt the actual (potentially large) message.

    Why hybrid? RSA is too slow to encrypt large data.
    AES is fast but requires a shared secret — RSA securely delivers that secret.

    OAEP Padding:
      - PKCS1_OAEP (Optimal Asymmetric Encryption Padding) adds randomness to RSA.
      - Without proper padding, RSA is deterministic and vulnerable to attacks.
      - OAEP is probabilistic: encrypting the same key twice gives different ciphertext.

    Args:
        aes_key (bytes):               The raw 16-byte AES session key to protect.
        recipient_public_key_pem (str): PEM-encoded RSA public key of the recipient.

    Returns:
        bytes: RSA-OAEP ciphertext of the AES key.
    """
    # Import the recipient's public key from its PEM representation
    recipient_pub_key = RSA.import_key(recipient_public_key_pem)

    # Create an OAEP cipher object using the recipient's public key
    # Public key exchange enables secure session key establishment
    cipher_rsa = PKCS1_OAEP.new(recipient_pub_key)

    # Encrypt the AES key — only the owner of the matching private key can decrypt this
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    return encrypted_aes_key


def decrypt_aes_key_with_rsa(encrypted_aes_key: bytes, private_key_pem: str) -> bytes:
    """
    Decrypt an RSA-protected AES session key using the recipient's private key.

    E2EE guarantee: Only the recipient (who holds the private key) can recover
    the AES key. The server never sees the private key and cannot perform this step.

    Args:
        encrypted_aes_key (bytes): RSA-OAEP ciphertext of the AES key.
        private_key_pem (str):     PEM-encoded RSA private key of the recipient.

    Returns:
        bytes: The original raw AES session key (16 bytes for AES-128).
    """
    # Import the recipient's private key — this key NEVER leaves the client machine
    # E2EE: Only sender and recipient hold keys — server is a blind relay
    private_key = RSA.import_key(private_key_pem)

    # Create an OAEP cipher object using the private key for decryption
    cipher_rsa = PKCS1_OAEP.new(private_key)

    # Recover the original AES key
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    return aes_key


# ─────────────────────────────────────────────────────────────────────────────
# AES-128-CBC Message Encryption
# ─────────────────────────────────────────────────────────────────────────────


def encrypt_message(plaintext: str, aes_key: bytes) -> tuple:
    """
    Encrypt a plaintext message using AES-128 in CBC mode.

    AES-CBC provides symmetric encryption for message confidentiality.

    CBC Mode (Cipher Block Chaining):
      - Each plaintext block is XOR'd with the PREVIOUS ciphertext block before encryption.
      - This means identical plaintext blocks produce DIFFERENT ciphertext blocks,
        hiding patterns in the data.
      - The first block uses the IV instead of a previous ciphertext block.

    IV (Initialization Vector):
      - Random IV prevents ciphertext pattern analysis (semantic security).
      - Without a random IV, encrypting the same message always produces the same ciphertext,
        allowing an attacker to detect repeated messages.
      - A fresh 16-byte IV is generated for EVERY message.

    PKCS7 Padding:
      - AES operates on fixed 16-byte blocks. If the message length isn't a multiple of 16,
        padding is added.
      - PKCS7 padding ensures plaintext fits AES block size (16 bytes).

    Args:
        plaintext (str): The human-readable message to encrypt.
        aes_key (bytes): The 16-byte AES session key.

    Returns:
        tuple: (iv: bytes, ciphertext: bytes)
               Both must be sent alongside the encrypted AES key to allow decryption.
    """
    # Generate a fresh random 16-byte IV for this specific message
    # Random IV prevents ciphertext pattern analysis (semantic security)
    iv = get_random_bytes(16)

    # Create an AES cipher in CBC mode with this key and IV
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

    # Encode the plaintext to bytes, then pad to a multiple of 16 bytes (block size)
    # PKCS7 padding ensures plaintext fits AES block size (16 bytes)
    padded_plaintext = pad(plaintext.encode("utf-8"), AES.block_size)

    # Encrypt the padded plaintext — the output is the ciphertext
    ciphertext = cipher_aes.encrypt(padded_plaintext)

    return iv, ciphertext


def decrypt_message(iv: bytes, ciphertext: bytes, aes_key: bytes) -> str:
    """
    Decrypt an AES-128-CBC ciphertext back into the original plaintext.

    Args:
        iv (bytes):         The 16-byte IV used during encryption.
        ciphertext (bytes): The AES-CBC encrypted message bytes.
        aes_key (bytes):    The 16-byte AES session key (recovered via RSA decryption).

    Returns:
        str: The decrypted plaintext message.
    """
    # Recreate the AES cipher with the same key and IV used for encryption
    # The IV must match exactly — using a different IV produces garbled output
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)

    # Decrypt the ciphertext to padded plaintext
    padded_plaintext = cipher_aes.decrypt(ciphertext)

    # Remove PKCS7 padding and decode bytes back to a string
    plaintext = unpad(padded_plaintext, AES.block_size).decode("utf-8")

    return plaintext


# ─────────────────────────────────────────────────────────────────────────────
# Full Hybrid Encrypt / Decrypt Helpers
# ─────────────────────────────────────────────────────────────────────────────


def hybrid_encrypt(plaintext: str, recipient_public_key_pem: str) -> dict:
    """
    Perform full hybrid encryption on a plaintext message for a specific recipient.

    Steps:
      1. Generate a fresh random 16-byte AES session key.
      2. Encrypt the message with AES-128-CBC using that key + a fresh random IV.
      3. Encrypt the AES key with the recipient's RSA public key (OAEP).
      4. Base64-encode all binary outputs for JSON serialization.

    Hybrid encryption: RSA for key exchange, AES for data encryption.

    Note on Data Integrity (for production systems):
      In a production E2EE system, an HMAC (Hash-based Message Authentication Code)
      or an RSA/ECDSA digital signature would be added here to verify:
        - The message was not tampered with in transit (integrity).
        - The message actually came from the claimed sender (authenticity / non-repudiation).
      This project focuses on confidentiality (encryption) as the primary demonstration.

    Args:
        plaintext (str):                The message to encrypt.
        recipient_public_key_pem (str): Recipient's RSA public key in PEM format.

    Returns:
        dict: {
            "encrypted_aes_key": <base64 str>,
            "iv":                <base64 str>,
            "ciphertext":        <base64 str>
        }
    """
    # Step 1: Generate a random 16-byte AES-128 session key (fresh per message)
    # AES-128 uses a 128-bit (16-byte) key — considered secure for most use cases
    aes_key = get_random_bytes(16)

    # Step 2: Encrypt the plaintext message with AES-128-CBC
    # AES-CBC provides symmetric encryption for message confidentiality
    iv, ciphertext = encrypt_message(plaintext, aes_key)

    # Step 3: Encrypt the AES key with the recipient's RSA public key
    # Hybrid encryption: RSA for key exchange, AES for data encryption
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, recipient_public_key_pem)

    # Step 4: Base64-encode binary fields so they can be embedded in JSON strings
    return {
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
    }


def hybrid_decrypt(
    encrypted_aes_key_b64: str, iv_b64: str, ciphertext_b64: str, private_key_pem: str
) -> str:
    """
    Perform full hybrid decryption to recover the original plaintext message.

    Steps:
      1. Base64-decode the binary fields from the JSON bundle.
      2. Decrypt the AES key using the recipient's RSA private key (OAEP).
      3. Decrypt the ciphertext using the recovered AES key + IV.

    E2EE: Only sender and recipient hold keys — server is a blind relay.

    Args:
        encrypted_aes_key_b64 (str): Base64-encoded RSA-encrypted AES key.
        iv_b64 (str):                Base64-encoded AES Initialization Vector.
        ciphertext_b64 (str):        Base64-encoded AES-CBC ciphertext.
        private_key_pem (str):       Recipient's RSA private key in PEM format.

    Returns:
        str: The decrypted plaintext message.
    """
    # Decode base64 fields back into raw bytes
    encrypted_aes_key = base64.b64decode(encrypted_aes_key_b64)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)

    # Recover the AES session key using the recipient's private key
    # E2EE: Only sender and recipient hold keys — server is a blind relay
    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, private_key_pem)

    # Decrypt the message using the recovered AES key and IV
    plaintext = decrypt_message(iv, ciphertext, aes_key)

    return plaintext
