import json
import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from getpass import getpass

# --- CONFIGURATION ---
DATA_FILE = "passwords.enc"  # The encrypted file where data is stored

class PasswordManager:
    def __init__(self):
        self.key = None
        self.password_dict = {}
        self.salt = None

    def _derive_key(self, master_password, salt):
        """
        Derives a secure 32-byte key from the master password using PBKDF2.
        This ensures the raw password is never stored or used directly as a key.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000, # High iteration count slows down brute-force attacks
        )
        return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

    def load_or_create(self):
        """Handles authentication or creating a new vault."""
        print("=== Secure Password Manager ===")
        
        if not os.path.exists(DATA_FILE):
            print("[!] No existing vault found. Let's create a new one.")
            while True:
                master_pass = getpass("Set a Master Password: ")
                confirm_pass = getpass("Confirm Master Password: ")
                
                if master_pass == confirm_pass and master_pass:
                    break
                print("[-] Passwords do not match or cannot be empty. Try again.")
            
            # Generate a random 16-byte salt
            self.salt = os.urandom(16)
            self.key = self._derive_key(master_pass, self.salt)
            self.save_data()
            print("[+] Vault created successfully!")
            return True
        else:
            # If file exists, prompt for login
            master_pass = getpass("Enter Master Password: ")
            
            # Read the file to get the salt and encrypted data
            with open(DATA_FILE, 'rb') as f:
                file_content = f.read()
            
            self.salt = file_content[:16]  # First 16 bytes are the salt
            encrypted_data = file_content[16:]
            
            # Derive the key using the input password and the stored salt
            self.key = self._derive_key(master_pass, self.salt)
            
            try:
                # Attempt to decrypt
                fernet = Fernet(self.key)
                decrypted_json = fernet.decrypt(encrypted_data).decode()
                self.password_dict = json.loads(decrypted_json)
                print("[+] Login successful.")
                return True
            except Exception:
                print("[-] ACCESS DENIED: Wrong password or corrupted file.")
                return False

    def save_data(self):
        """Encrypts the dictionary and saves it to disk."""
        fernet = Fernet(self.key)
        json_data = json.dumps(self.password_dict)
        encrypted_data = fernet.encrypt(json_data.encode())
        
        # Save Salt + Encrypted Data together
        with open(DATA_FILE, 'wb') as f:
            f.write(self.salt + encrypted_data)

    def add_password(self):
        service = input("Service Name (e.g., Gmail): ").strip()
        username = input("Username: ").strip()
        password = getpass("Password: ").strip() # Hides input for security
        
        if service and username and password:
            self.password_dict[service] = {"username": username, "password": password}
            self.save_data()
            print(f"[+] Credentials for '{service}' saved successfully.")
        else:
            print("[-] Error: Fields cannot be empty.")

    def get_password(self):
        service = input("Enter Exact Service Name to retrieve: ").strip()
        if service in self.password_dict:
            creds = self.password_dict[service]
            print(f"\n--- Details for {service} ---")
            print(f"Username: {creds['username']}")
            print(f"Password: {creds['password']}")
        else:
            print("[-] Service not found.")

    def search_password(self):
        """Allows searching for a service (e.g., 'goo' finds 'google')."""
        query = input("Search query: ").lower()
        results = [s for s in self.password_dict if query in s.lower()]
        
        if results:
            print(f"\n[+] Found {len(results)} matches:")
            for res in results:
                print(f" - {res}")
        else:
            print("[-] No matches found.")

    def delete_password(self):
        service = input("Enter Service Name to delete: ").strip()
        if service in self.password_dict:
            del self.password_dict[service]
            self.save_data()
            print(f"[+] Entry '{service}' deleted.")
        else:
            print("[-] Service not found.")

def main():
    pm = PasswordManager()
    if not pm.load_or_create():
        return

    while True:
        print("\n" + "="*30)
        print("1. Add New Password")
        print("2. Retrieve Password")
        print("3. Search Passwords")
        print("4. Delete Password")
        print("5. Exit")
        
        choice = input("Select Option (1-5): ")
        
        if choice == '1': pm.add_password()
        elif choice == '2': pm.get_password()
        elif choice == '3': pm.search_password()
        elif choice == '4': pm.delete_password()
        elif choice == '5': 
            print("Exiting and securing vault...")
            break
        else: 
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()