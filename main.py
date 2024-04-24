import os

from Crypto.Cipher import AES

from Crypto.Random import get_random_bytes



# Function to install dependencies

def install_dependencies():

    try:

        print("Installing required packages...")

        os.system("sudo apt update")

        os.system("sudo apt install -y python3-pip")

        os.system("sudo apt install -y python3-dev")

        os.system("pip3 install pycryptodome")

    except Exception as e:

        print(f"Failed to install dependencies: {e}")

        exit(1)



# Function to encrypt a file

def encrypt_file(file_path, key):

    try:

        with open(file_path, 'rb') as file:

            plaintext = file.read()



        cipher = AES.new(key, AES.MODE_EAX)  # Using EAX mode

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)



        with open(file_path + '.enc', 'wb') as file:

            [file.write(x) for x in (cipher.nonce, tag, ciphertext)]



        print(f"\033[95mEncryption completed. Encrypted file saved as: {file_path}.enc\033[0m")

        return True

    except Exception as e:

        print(f"\033[91mEncryption failed: {e}\033[0m")

        return False



# Function to decrypt a file

def decrypt_file(file_path, key):

    try:

        with open(file_path, 'rb') as file:

            nonce, tag, ciphertext = [file.read(x) for x in (16, 16, -1)]



        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

        plaintext = cipher.decrypt_and_verify(ciphertext, tag)



        with open(file_path[:-4], 'wb') as file:

            file.write(plaintext)



        print(f"\033[92mDecryption completed. Decrypted file saved as: {file_path[:-4]}\033[0m")

    except Exception as e:

        print(f"\033[91mDecryption failed: {e}\033[0m")



# Function to generate a specific decryption key

def generate_key():

    return get_random_bytes(32)  # Generate a random 256-bit key



# Function to display decrypted files and encrypt a selected file

def display_and_encrypt_files(key):

    decrypted_files = [file for file in os.listdir() if not file.endswith('.enc')]

    if not decrypted_files:

        print("\033[93mNo decrypted files found in the directory.\033[0m")

    else:

        print("\033[93mDecrypted files in the directory:\033[0m")

        for index, file_name in enumerate(decrypted_files):

            print(f"{index}: {file_name}")



    file_path = input("\033[92mEnter the name of the file to encrypt along with extension:\033[0m ")

    if os.path.isfile(file_path):

        encryption_key = generate_key()

        if encrypt_file(file_path, encryption_key):

            print(f"\033[90mDecryption key for {file_path}: {encryption_key.hex()}\033[0m")

    else:

        print("\033[91mFile not found.\033[0m")



# Function to display encrypted files and decrypt a selected file

def display_and_decrypt_files(key):

    encrypted_files = [file for file in os.listdir() if file.endswith('.enc')]

    if not encrypted_files:

        print("\033[93mEnter the name of file that you want to encrypt. (along with extension).\033[0m")

    else:

        print("\033[96mEncrypted files in the directory:\033[0m")

        for index, file_name in enumerate(encrypted_files):

            print(f"{index}: {file_name}")



        file_name = input("\033[94mEnter the name of the file to decrypt (along with extension.Eg:- aa.txt,photo.jpeg)\n Do not enter .enc in extension: \033[0m")

        file_path = file_name + '.enc'

        if file_path in encrypted_files:

            decryption_key = input("\033[94mEnter the decryption key: \033[0m")

            decrypt_file(file_path, bytes.fromhex(decryption_key))

        else:

            print("\033[91mFile not found or not encrypted.\033[0m")



# Main function

def main():

    install_dependencies()

    key = get_random_bytes(32)  # Generate a random 256-bit key



    # Print the banner

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

        print("\033[96mChoose an option:\033[0m")

        print("\033[92m0 - Encrypt file\033[0m")

        print("\033[93m1 - Decrypt file\033[0m")

        print("\033[91m2 - Exit\033[0m")



        option = input("\033[94mOption: \033[0m")



        if option == '0':

            display_and_encrypt_files(key)

        elif option == '1':

            display_and_decrypt_files(key)

        elif option == '2':

            print("\033[91mExiting...\033[0m")

            break

        else:

            print("\033[91mInvalid option! Please choose again.\033[0m")



if __name__ == "__main__":

    main()
