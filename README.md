# Secure Password Manager 🔐

A secure, local command-line password manager built with Python. This tool implements industry-standard encryption to safely store and retrieve credentials locally. 

*Developed as part of the Cyber Security Internship at **SyntexHub**.*

## 🚀 Features
- **AES-128 Encryption:** Uses the Fernet symmetric encryption standard.
- **Secure Key Derivation:** Implements **PBKDF2HMAC** with SHA-256 and a random salt to prevent Rainbow Table attacks.
- **Zero-Knowledge Architecture:** The master password is never stored; the encryption key is derived dynamically at runtime.
- **Search Functionality:** Quickly find credentials by service name.
- **CRUD Operations:** Add, Retrieve, Delete, and List passwords easily.

## 🛠️ Tech Stack
- **Language:** Python 3.x
- **Library:** `cryptography` (for cryptographic primitives)
- **Algorithm:** AES (CBC mode via Fernet) + PBKDF2HMAC

## 📦 Installation & Usage

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/hamza0103/Secure-Password-Manager.git](https://github.com/hamza0103/Secure-Password-Manager.git)
   cd Secure-Password-Manager
