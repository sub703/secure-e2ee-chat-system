"""
auth.py
=======
User authentication module for the E2EE Chat System.

Role in the system:
  - Provides a simple in-memory user registry (username → hashed password).
  - Supports user registration and login using SHA-256 password hashing.
  - Passwords are NEVER stored or transmitted in plaintext.

Subject: Data Encryption and Network Security
Concepts: SHA-256 One-Way Hashing, Password Security, Authentication
"""

import hashlib

# ─────────────────────────────────────────────────────────────────────────────
# In-memory user store:  { username: sha256_hex_digest_of_password }
#
# In a production system this would be replaced by a persistent database
# (e.g., PostgreSQL) with a proper key-derivation function such as bcrypt,
# scrypt, or Argon2, which add a cost factor to slow down brute-force attacks.
# SHA-256 is used here to demonstrate the hashing concept clearly.
# ─────────────────────────────────────────────────────────────────────────────
_user_store: dict = {}


def _hash_password(password: str) -> str:
    """
    Compute the SHA-256 hash of a plaintext password.

    SHA-256 is a one-way cryptographic hash function:
      - Given a hash, it is computationally infeasible to recover the original password.
      - The same password always produces the same hash (deterministic).
      - Even a single character change produces a completely different hash (avalanche effect).

    SHA-256 one-way hash protects passwords at rest.

    Note: For production use, a salted hash (e.g., bcrypt) is preferred because it
    defends against rainbow-table attacks (pre-computed hash lookup tables).
    A salt is a unique random value prepended to the password before hashing,
    making each stored hash unique even for identical passwords.

    Args:
        password (str): The user's plaintext password.

    Returns:
        str: The hexadecimal SHA-256 digest (64 hex characters = 256 bits).
    """
    # SHA-256 one-way hash protects passwords at rest
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def register_user(username: str, password: str) -> tuple:
    """
    Register a new user with a hashed password.

    The plaintext password is hashed immediately and never stored anywhere.
    Only the SHA-256 digest is kept in the user store.

    Args:
        username (str): Desired username (must be unique).
        password (str): Plaintext password chosen by the user.

    Returns:
        tuple: (success: bool, message: str)
               success=True if registration succeeded,
               success=False if the username already exists or input is invalid.
    """
    if not username or not password:
        return False, "Username and password cannot be empty."

    if username in _user_store:
        return False, f"Username '{username}' is already taken. Please choose another."

    # Hash the password before storing — plaintext never touches the store
    _user_store[username] = _hash_password(password)

    return True, f"User '{username}' registered successfully. You can now log in."


def login_user(username: str, password: str) -> tuple:
    """
    Authenticate a user by comparing hashed passwords.

    How it works:
      1. The entered password is hashed with SHA-256.
      2. The hash is compared to the stored hash for that username.
      3. If they match, authentication succeeds.
      4. The plaintext password is never stored, logged, or transmitted.

    This prevents password exposure even if the user store is leaked,
    because an attacker would only see hash digests.

    Args:
        username (str): The username to authenticate.
        password (str): The plaintext password entered by the user.

    Returns:
        tuple: (success: bool, message: str)
               success=True if credentials are valid,
               success=False otherwise.
    """
    if username not in _user_store:
        return False, "Username not found. Please register first."

    # Hash the entered password and compare with the stored hash
    # SHA-256 one-way hash protects passwords at rest
    entered_hash = _hash_password(password)
    stored_hash = _user_store[username]

    if entered_hash == stored_hash:
        return True, f"Welcome back, {username}! Login successful."
    else:
        return False, "Incorrect password. Please try again."


def user_exists(username: str) -> bool:
    """
    Check whether a username is already registered.

    Args:
        username (str): The username to look up.

    Returns:
        bool: True if the username exists in the user store, False otherwise.
    """
    return username in _user_store


def get_all_users() -> list:
    """
    Return a list of all registered usernames.

    Used by the client to populate the recipient dropdown on the chat screen.

    Returns:
        list[str]: A sorted list of all registered usernames.
    """
    return sorted(_user_store.keys())
