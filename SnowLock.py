from Crypto.Cipher import AES
from zlib import compress, decompress
import argparse
import os
from hashlib import md5, blake2s

parser = argparse.ArgumentParser(description="Encrypts or decrypts a file with an associated password.")

sub_parser = parser.add_subparsers(dest='command')

encrypt = sub_parser.add_parser('encrypt')
encrypt.add_argument("-f", "--file", required=True, help="File path to the file to be encrypted.")
encrypt.add_argument("-p", "--password", required=True, help="Password to be used to encrypt file.")
encrypt.add_argument("-o", "--output", help="File path to output file to. [Keeps the original file.]")

decrypt = sub_parser.add_parser('decrypt')
decrypt.add_argument("-f", "--file", required=True, help="File path to the file to be decrypted.")
decrypt.add_argument("-p", "--password", required=True, help="Password to be used to decrypt file.")
decrypt.add_argument("-o", "--output", help="File path to output file to. [Keeps the original file.]")

args = parser.parse_args()

MAGIC_BYTES = b"\x77\x58\x31\xFE\x00\x01\x00\x01"


def pad(file):
    while len(file) % 16 != 0:
        file += b"\x00"
    return file


def generate_key(password):
    return md5(password.encode("utf-8")).digest()


def generate_iv(password):
    return blake2s(password.encode("utf-8"), digest_size=16).digest()


def check_magic_bytes(file, password):
    cipher = AES.new(key=generate_key(password), iv=generate_iv(password), mode=AES.MODE_CBC)
    return cipher.decrypt(file)[0:8] == MAGIC_BYTES


def encrypt(file, password):
    comp_file = compress(file, 9)
    cipher = AES.new(key=generate_key(password), iv=generate_iv(password), mode=AES.MODE_CBC)
    return cipher.encrypt(pad(MAGIC_BYTES + comp_file))


def decrypt(file, password):
    if check_magic_bytes(file, password):
        cipher = AES.new(key=generate_key(password), iv=generate_iv(password), mode=AES.MODE_CBC)
        return decompress(cipher.decrypt(file)[8:])
    else:
        print("[-] Magic bytes not detected, please verify you used the correct password.")
        return None


def main():
    if args.command is None:
        print(f"Usage: python {os.path.basename(__file__)} {{encrypt | decrypt}} [-h] -f FILE -p PASSWORD [-o OUTPUT]")
        return

    elif not os.path.exists(args.file):
        print("[-] Please provide a valid file path to a file that exists.")
        return

    elif os.path.isdir(args.file):
        print("[-] Please provide a valid file path to a file that is not a directory.")
        return

    elif args.command == "encrypt":
        if args.output is not None:
            with open(args.file, "rb") as f:
                file = f.read()
                with open(args.output, "wb") as j:
                    file = encrypt(file, args.password)
                    j.write(file)
                    print("[+] File successfully encrypted.")

        else:
            with open(args.file, "rb") as f:
                file = f.read()
                f.close()
            with open(args.file, "wb") as f:
                enc_file = encrypt(file, args.password)
                f.write(enc_file)
                print("[+] File successfully encrypted.")

    elif args.command == "decrypt":
        if args.output is not None:
            with open(args.file, "rb") as f:
                file = f.read()
                with open(args.output, "wb") as j:
                    dec_file = decrypt(file, args.password)
                    if dec_file is None:
                        os.remove(args.output)
                    else:
                        j.write(dec_file)
                        print("[+] File successfully decrypted.")

        else:
            with open(args.file, "rb") as f:
                file = f.read()
                f.close()
            with open(args.file, "wb") as f:
                dec_file = decrypt(file, args.password)
                if dec_file is None:
                    f.write(file)
                else:
                    f.write(dec_file)
                    print("[+] File successfully decrypted.")


if __name__ == '__main__':
    main()
