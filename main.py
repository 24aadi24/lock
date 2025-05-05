import os
import subprocess
import sys

try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.PublicKey import ECC
    from Cryptodome.Hash import SHA256
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pycryptodome"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    from Cryptodome.PublicKey import ECC
    from Cryptodome.Hash import SHA256

def generate_key():
    return get_random_bytes(32)

def encrypt_file(file_path, key):
    try:
        original_ext = os.path.splitext(file_path)[1]
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        ext_bytes = original_ext.encode().ljust(10, b'\x00')  # Fixed 10 bytes
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(ext_bytes + plaintext)

        base = os.path.splitext(file_path)[0]
        output_path = base + "_enc"
        with open(output_path, 'wb') as f:
            f.write(cipher.nonce + tag + ciphertext)

        print(f"\033[95mEncryption completed: {output_path}\033[0m")
        return key
    except Exception as e:
        print(f"\033[91mEncryption failed: {e}\033[0m")
        return None

def decrypt_file(file_path, key):
    try:
        with open(file_path, 'rb') as f:
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        ext = decrypted[:10].rstrip(b'\x00').decode()
        plaintext = decrypted[10:]

        base = file_path.replace('_enc', '')
        output_path = base + ext
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"\033[92mDecryption completed: {output_path}\033[0m")
    except Exception as e:
        print(f"\033[91mDecryption failed: {e}\033[0m")

def ensure_ecc_keys_exist():
    if not (os.path.exists("ecc_private.pem") and os.path.exists("ecc_public.pem")):
        private_key = ECC.generate(curve='P-256')
        public_key = private_key.public_key()
        with open("ecc_private.pem", "wt") as f:
            f.write(private_key.export_key(format='PEM'))
        with open("ecc_public.pem", "wt") as f:
            f.write(public_key.export_key(format='PEM'))

def ecc_encrypt_file(file_path):
    try:
        ensure_ecc_keys_exist()
        with open("ecc_public.pem", "rt") as f:
            public_key = ECC.import_key(f.read())

        ephemeral_key = ECC.generate(curve='P-256')
        shared_point = public_key.pointQ * ephemeral_key.d
        x = int(shared_point.x)
        aes_key = SHA256.new(x.to_bytes((x.bit_length() + 7) // 8, 'big')).digest()

        original_ext = os.path.splitext(file_path)[1].encode().ljust(10, b'\x00')
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        cipher = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(original_ext + plaintext)

        output_path = os.path.splitext(file_path)[0] + "_ecc"
        with open(output_path, 'wb') as f:
            f.write(ephemeral_key.public_key().export_key(format='DER'))
            f.write(cipher.nonce + tag + ciphertext)

        print(f"\033[95mECC Encryption completed: {output_path}\033[0m")
    except Exception as e:
        print(f"\033[91mECC Encryption failed: {e}\033[0m")

def ecc_decrypt_file(file_path):
    try:
        ensure_ecc_keys_exist()
        with open("ecc_private.pem", "rt") as f:
            private_key = ECC.import_key(f.read())

        with open(file_path, 'rb') as f:
            ephemeral_der = f.read(91)
            ephemeral_key = ECC.import_key(ephemeral_der)
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        shared_point = ephemeral_key.pointQ * private_key.d
        x = int(shared_point.x)
        aes_key = SHA256.new(x.to_bytes((x.bit_length() + 7) // 8, 'big')).digest()

        cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        ext = decrypted[:10].rstrip(b'\x00').decode()
        plaintext = decrypted[10:]

        base = file_path.replace('_ecc', '')
        output_path = base + ext
        with open(output_path, 'wb') as f:
            f.write(plaintext)

        print(f"\033[92mECC Decryption completed: {output_path}\033[0m")
    except Exception as e:
        print(f"\033[91mECC Decryption failed: {e}\033[0m")

# === UI Functions (no change except minor messages) ===
def display_and_encrypt_files():
    files = [f for f in os.listdir() if os.path.isfile(f) and not f.endswith(('_enc', '_ecc'))]
    if not files:
        print("\033[93mNo files available for encryption.\033[0m")
        return
    print("\033[93mFiles to encrypt:\033[0m")
    for f in files:
        print(f"- {f}")
    file_name = input("\033[92mEnter filename to encrypt:\033[0m ").strip()
    if os.path.isfile(file_name):
        key = generate_key()
        result = encrypt_file(file_name, key)
        if result:
            print(f"\033[90mSave this key securely:\n{key.hex()}\033[0m")
    else:
        print("\033[91mFile not found.\033[0m")

def display_and_decrypt_files():
    enc_files = [f for f in os.listdir() if f.endswith('_enc')]
    if not enc_files:
        print("\033[93mNo encrypted files found.\033[0m")
        return
    print("\033[96mEncrypted files:\033[0m")
    for f in enc_files:
        print(f"- {f}")
    file_name = input("\033[94mEnter filename to decrypt:\033[0m ").strip()
    if os.path.isfile(file_name):
        key_input = input("\033[94mEnter decryption key (hex):\033[0m ").strip()
        try:
            key = bytes.fromhex(key_input)
            decrypt_file(file_name, key)
        except ValueError:
            print("\033[91mInvalid hex key format.\033[0m")
    else:
        print("\033[91mFile not found.\033[0m")

def display_and_encrypt_ecc_files():
    files = [f for f in os.listdir() if os.path.isfile(f) and not f.endswith(('_enc', '_ecc'))]
    if not files:
        print("\033[93mNo files for ECC encryption.\033[0m")
        return
    print("\033[93mFiles to ECC encrypt:\033[0m")
    for f in files:
        print(f"- {f}")
    file_name = input("\033[92mEnter filename to ECC encrypt:\033[0m ").strip()
    if os.path.isfile(file_name):
        ecc_encrypt_file(file_name)
    else:
        print("\033[91mFile not found.\033[0m")

def display_and_decrypt_ecc_files():
    ecc_files = [f for f in os.listdir() if f.endswith('_ecc')]
    if not ecc_files:
        print("\033[93mNo ECC-encrypted files.\033[0m")
        return
    print("\033[96mECC Encrypted files:\033[0m")
    for f in ecc_files:
        print(f"- {f}")
    file_name = input("\033[94mEnter ECC filename:\033[0m ").strip()
    if os.path.isfile(file_name):
        ecc_decrypt_file(file_name)
    else:
        print("\033[91mFile not found.\033[0m")

def main():
    print("\033[95m")
    print("""
888      .d88888b.   .d8888b.  888    d8P  
888     d88P" "Y88b d88P  Y88b 888   d8P   
888     888     888 888    888 888  d8P    
888     888     888 888        888d88K     
888     888     888 888        8888888b    
888     888     888 888    888 888  Y88b   
888     Y88b. .d88P Y88b  d88P 888   Y88b  
88888888 "Y88888P"   "Y8888P"  888    Y88b 
""")
    print("\033[0m")
    while True:
        print("\033[96mSelect an option:\033[0m")
        print("\033[92m0 - Encrypt a file (AES)\033[0m")
        print("\033[93m1 - Decrypt a file (AES)\033[0m")
        print("\033[92m2 - Encrypt a file with ECC (no key needed)\033[0m")
        print("\033[93m3 - Decrypt ECC-encrypted file\033[0m")
        print("\033[91m4 - Exit\033[0m")
        option = input("\033[94mOption: \033[0m ").strip()
        if option == '0':
            display_and_encrypt_files()
        elif option == '1':
            display_and_decrypt_files()
        elif option == '2':
            display_and_encrypt_ecc_files()
        elif option == '3':
            display_and_decrypt_ecc_files()
        elif option == '4':
            print("\033[91mExiting...\033[0m")
            break
        else:
            print("\033[91mInvalid choice. Try again.\033[0m")

if __name__ == "__main__":
    main()
