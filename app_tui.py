import sys
import os
import struct
import math
import zlib
import getpass
from pathlib import Path

from PIL import Image

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# -------------------------------------------------------------------
# CONSTANTS
# -------------------------------------------------------------------

MAGIC = b"STEG"
CHUNK_HEADER_FMT = ">4sBBI"
CHUNK_HEADER_SIZE = struct.calcsize(CHUNK_HEADER_FMT)
MAX_CHUNKS = 255
PBKDF2_ITERATIONS = 600_000

PAYLOAD_TYPE_TEXT = 0x00
PAYLOAD_TYPE_FILE = 0x01
PAYLOAD_HEADER_FMT = ">BH"
PAYLOAD_HEADER_SIZE = struct.calcsize(PAYLOAD_HEADER_FMT)

# -------------------------------------------------------------------
# BIT-LEVEL UTILITIES
# -------------------------------------------------------------------

def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

def bits_to_bytes(bits: list[int] | bytearray) -> bytes:
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i+8]
        byte_val = 0
        for bit in chunk:
            byte_val = (byte_val << 1) | bit
        out.append(byte_val)
    return bytes(out)

def split_bytes(data: bytes, n: int) -> list[bytes]:
    k, m = divmod(len(data), n)
    return [data[i * k + min(i, m):(i + 1) * k + min(i + 1, m)] for i in range(n)]

# -------------------------------------------------------------------
# CRYPTOGRAPHY
# -------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_data(data: bytes, password: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return salt + iv + encryptor.tag + ciphertext

def decrypt_data(encrypted_payload: bytes, password: str) -> bytes:
    if len(encrypted_payload) < 44:
        raise ValueError("Incomplete or corrupted encrypted data.")

    salt = encrypted_payload[:16]
    iv = encrypted_payload[16:28]
    tag = encrypted_payload[28:44]
    ciphertext = encrypted_payload[44:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# -------------------------------------------------------------------
# PAYLOAD ENVELOPE
# -------------------------------------------------------------------

def build_payload(data: bytes, filename: str | None) -> bytes:
    if filename is None:
        payload_type = PAYLOAD_TYPE_TEXT
        name_bytes = b""
    else:
        payload_type = PAYLOAD_TYPE_FILE
        name_bytes = filename.encode("utf-8")
        if len(name_bytes) > 0xFFFF:
            raise ValueError("The filename is too long.")

    header = struct.pack(PAYLOAD_HEADER_FMT, payload_type, len(name_bytes))
    return header + name_bytes + data

def parse_payload(raw: bytes) -> tuple[bool, str | None, bytes]:
    if len(raw) < PAYLOAD_HEADER_SIZE:
        raise ValueError("Invalid or corrupted payload.")

    payload_type, name_len = struct.unpack(PAYLOAD_HEADER_FMT, raw[:PAYLOAD_HEADER_SIZE])
    offset = PAYLOAD_HEADER_SIZE

    if len(raw) < offset + name_len:
        raise ValueError("Invalid or corrupted payload (truncated filename).")

    filename = None
    if payload_type == PAYLOAD_TYPE_FILE:
        filename = raw[offset:offset + name_len].decode("utf-8")
    offset += name_len

    data = raw[offset:]
    return payload_type == PAYLOAD_TYPE_FILE, filename, data

# -------------------------------------------------------------------
# SPATIAL STEGANOGRAPHY
# -------------------------------------------------------------------

def image_capacity_bytes(image_path: str) -> int:
    with Image.open(image_path) as img:
        w, h = img.size
    total_bits = w * h * 3
    return max(0, total_bits // 8 - CHUNK_HEADER_SIZE)

def embed_chunk(cover_path: str, output_path: str, chunk_bytes: bytes, chunk_index: int, total_chunks: int):
    header = struct.pack(CHUNK_HEADER_FMT, MAGIC, total_chunks, chunk_index, len(chunk_bytes))
    payload = header + chunk_bytes
    bits = bytes_to_bits(payload)
    num_bits = len(bits)

    img = Image.open(cover_path).convert("RGB")
    w, h = img.size

    if num_bits > w * h * 3:
        scale = math.sqrt(num_bits / (w * h * 3))
        new_w = int(math.ceil(w * scale))
        new_h = int(math.ceil(h * scale))
        
        while new_w * new_h * 3 < num_bits:
            new_w += 1
            new_h += 1
            
        img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)
        w, h = img.size

    img_bytes = bytearray(img.tobytes())

    for i in range(num_bits):
        img_bytes[i] = (img_bytes[i] & 0xFE) | bits[i]

    stego_img = Image.frombytes("RGB", (w, h), bytes(img_bytes))
    stego_img.save(output_path, format="PNG", optimize=True)

def extract_chunk(stego_path: str) -> tuple[int, int, bytes]:
    img = Image.open(stego_path).convert("RGB")
    img_bytes = img.tobytes()
    total_bytes_count = len(img_bytes)

    header_bit_count = CHUNK_HEADER_SIZE * 8
    if total_bytes_count < header_bit_count:
        raise ValueError(f"Image '{os.path.basename(stego_path)}' is too small.")

    header_bits = [img_bytes[i] & 1 for i in range(header_bit_count)]
    header_bytes = bits_to_bytes(header_bits)

    magic, total_chunks, chunk_index, chunk_len = struct.unpack(CHUNK_HEADER_FMT, header_bytes)
    if magic != MAGIC:
        raise ValueError(f"Image '{os.path.basename(stego_path)}' does not contain valid data.")

    total_bits = (CHUNK_HEADER_SIZE + chunk_len) * 8
    if total_bits > total_bytes_count:
        raise ValueError(f"Image '{os.path.basename(stego_path)}' appears corrupted.")

    payload_bits = [img_bytes[i] & 1 for i in range(total_bits)]
    payload_bytes = bits_to_bytes(payload_bits)

    return chunk_index, total_chunks, payload_bytes[CHUNK_HEADER_SIZE:]

# -------------------------------------------------------------------
# TUI INTERFACE (Terminal User Interface)
# -------------------------------------------------------------------

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def pause():
    input("\nPress Enter to continue...")

class StegoTUI:
    def __init__(self):
        # Embed state
        self.embed_images = []
        self.embed_mode = "text"  # "text" or "file"
        self.embed_text = ""
        self.embed_file = ""
        self.embed_pass = ""

        # Extract state
        self.extract_images = []
        self.extract_pass = ""

    def run(self):
        while True:
            clear_screen()
            print("======================================================")
            print(" PHOTOCRYPT TUI 0.01 - Hide and Encrypt Data in Images")
            print("======================================================\n")
            print("1. Embed")
            print("2. Extract")
            print("3. Quit\n")
            
            choice = input("Choose an option: ").strip()
            if choice == '1':
                self.menu_embed()
            elif choice == '2':
                self.menu_extract()
            elif choice == '3':
                print("Goodbye.")
                break

    def calculate_capacity(self):
        if not self.embed_images:
            return "Total capacity: —"
        try:
            total_cap = sum(image_capacity_bytes(img) for img in self.embed_images)
        except Exception:
            return "Total capacity: (read error)"

        if self.embed_mode == "file":
            raw_size = os.path.getsize(self.embed_file) if (self.embed_file and os.path.exists(self.embed_file)) else 0
            name_len = len(os.path.basename(self.embed_file).encode("utf-8")) if self.embed_file else 0
        else:
            raw_size = len(self.embed_text.encode("utf-8"))
            name_len = 0

        needed = raw_size + name_len + PAYLOAD_HEADER_SIZE + 44 + len(self.embed_images) * CHUNK_HEADER_SIZE
        status = "OK" if needed <= total_cap else "Auto-resizing"
        return f"Base capacity: {total_cap} bytes — estimated need: {needed} bytes [{status}]"

    def menu_embed(self):
        while True:
            clear_screen()
            print("=== TAB: EMBED ===\n")
            
            print("[ 1. Select source images ]")
            if not self.embed_images:
                print("  No image selected.")
            else:
                for idx, img in enumerate(self.embed_images):
                    print(f"  {idx+1}. {os.path.basename(img)}")
            print(f"  > {self.calculate_capacity()}\n")

            print("[ 2. Data to hide ]")
            print(f"  Current mode: {self.embed_mode.capitalize()}")
            if self.embed_mode == "text":
                preview = self.embed_text[:40] + "..." if len(self.embed_text) > 40 else (self.embed_text or "(empty)")
                print(f"  Text: {preview}")
            else:
                f_text = self.embed_file if self.embed_file else "(no file)"
                print(f"  File: {f_text}\n")
            
            print("[ 3. Password ]")
            pass_status = "Set" if self.embed_pass else "Not set"
            print(f"  Password: {pass_status}\n")

            print("--- ACTIONS ---")
            print("(A) Add images            (V) Clear images")
            print("(M) Toggle mode (Txt/File)(S) Enter secret data")
            print("(P) Set password          (E) Generate image set")
            print("(R) Return to main menu")
            
            choice = input("\nAction: ").strip().lower()

            if choice == 'a':
                paths = input("Image paths (comma-separated): ").split(',')
                for p in paths:
                    p = p.strip()
                    if os.path.isfile(p):
                        self.embed_images.append(p)
                    else:
                        print(f"File not found: {p}")
                pause()
            elif choice == 'v':
                self.embed_images.clear()
            elif choice == 'm':
                self.embed_mode = "file" if self.embed_mode == "text" else "text"
            elif choice == 's':
                if self.embed_mode == "text":
                    self.embed_text = input("Enter the text to hide: ")
                else:
                    f = input("Path of the file to hide: ").strip()
                    if os.path.isfile(f):
                        self.embed_file = f
                    else:
                        print("File not found.")
                        pause()
            elif choice == 'p':
                p1 = getpass.getpass("Password: ")
                p2 = getpass.getpass("Confirm Password: ")
                if p1 == p2 and p1:
                    self.embed_pass = p1
                else:
                    print("Error: Passwords are empty or do not match.")
                    pause()
            elif choice == 'e':
                self.run_embedding()
            elif choice == 'r':
                break

    def run_embedding(self):
        if not self.embed_images:
            print("\nError: Please add at least one image.")
            pause()
            return
        if not self.embed_pass:
            print("\nError: Password is required.")
            pause()
            return

        if self.embed_mode == "file":
            if not self.embed_file or not os.path.isfile(self.embed_file):
                print("\nError: Invalid file to hide.")
                pause(); return
            with open(self.embed_file, "rb") as f:
                secret_bytes = f.read()
            filename = os.path.basename(self.embed_file)
        else:
            if not self.embed_text:
                print("\nError: Text is empty.")
                pause(); return
            secret_bytes = self.embed_text.encode("utf-8")
            filename = None

        if len(self.embed_images) > MAX_CHUNKS:
            print(f"\nError: Too many images (maximum {MAX_CHUNKS}).")
            pause(); return

        out_dir = input("\nOutput directory: ").strip()
        if not out_dir: return

        print("\nProcessing...")
        try:
            num_images = len(self.embed_images)
            raw_payload = build_payload(secret_bytes, filename)
            compressed_payload = zlib.compress(raw_payload, level=9)
            encrypted_payload = encrypt_data(compressed_payload, self.embed_pass)
            chunks = split_bytes(encrypted_payload, num_images)

            os.makedirs(out_dir, exist_ok=True)

            for i, cover_path in enumerate(self.embed_images):
                chunk_bytes = chunks[i]
                out_path = os.path.join(out_dir, f"stego_part_{i + 1:02d}.png")
                embed_chunk(cover_path, out_path, chunk_bytes, chunk_index=i, total_chunks=num_images)
                print(f"Progress: {int(((i + 1) / num_images) * 100)}%")

            print(f"\nSuccess! Data hidden in {num_images} image(s):\n{out_dir}")
        except Exception as e:
            print(f"\nError during embedding: {e}")
        pause()

    def menu_extract(self):
        while True:
            clear_screen()
            print("=== TAB: EXTRACT ===\n")
            
            print("[ 1. Select ALL stego images from the set (.png) ]")
            if not self.extract_images:
                print("  No image selected.")
            else:
                for idx, img in enumerate(self.extract_images):
                    print(f"  {idx+1}. {os.path.basename(img)}")
            print()

            print("[ 2. Password ]")
            pass_status = "Set" if self.extract_pass else "Not set"
            print(f"  Password: {pass_status}\n")

            print("--- ACTIONS ---")
            print("(A) Add images            (V) Clear images")
            print("(P) Set password          (E) Decrypt data")
            print("(R) Return to main menu")

            choice = input("\nAction: ").strip().lower()

            if choice == 'a':
                paths = input("Image paths (comma-separated): ").split(',')
                for p in paths:
                    p = p.strip()
                    if os.path.isfile(p):
                        self.extract_images.append(p)
                    else:
                        print(f"File not found: {p}")
                pause()
            elif choice == 'v':
                self.extract_images.clear()
            elif choice == 'p':
                p1 = getpass.getpass("Decryption Password: ")
                if p1:
                    self.extract_pass = p1
            elif choice == 'e':
                self.run_extraction()
            elif choice == 'r':
                break

    def run_extraction(self):
        if not self.extract_images:
            print("\nError: Please select the stego images.")
            pause(); return
        if not self.extract_pass:
            print("\nError: Password is required.")
            pause(); return

        print("\nExtracting...")
        try:
            found = {}
            expected_total = None
            n = len(self.extract_images)

            for i, stego_path in enumerate(self.extract_images):
                chunk_index, total_chunks, chunk_bytes = extract_chunk(stego_path)

                if expected_total is None:
                    expected_total = total_chunks
                elif total_chunks != expected_total:
                    raise ValueError(f"Mismatch detected in '{os.path.basename(stego_path)}'.")

                if chunk_index in found:
                    raise ValueError(f"Duplicate chunk {chunk_index}.")

                found[chunk_index] = chunk_bytes
                print(f"Progress: {int(((i + 1) / n) * 100)}%")

            if expected_total is None or len(found) != expected_total:
                raise ValueError("Missing chunks. Select all images from the original set.")

            full_payload = b"".join(found[i] for i in range(expected_total))
            decrypted_compressed = decrypt_data(full_payload, self.extract_pass)
            
            try:
                decrypted_raw = zlib.decompress(decrypted_compressed)
            except zlib.error:
                raise ValueError("Decompression failed: corrupted data or incorrect password.")
                
            is_file, filename, data = parse_payload(decrypted_raw)
            
            print("\n--- RESULT ---")
            if is_file:
                print(f"File detected: {filename}")
                print(f"Size: {len(data)} bytes")
                save_path = input("\nSave path (leave empty to cancel): ").strip()
                if save_path:
                    with open(save_path, "wb") as f:
                        f.write(data)
                    print(f"File saved as: {save_path}")
            else:
                print("Secret text:\n")
                print(data.decode("utf-8"))
        except Exception as e:
            print(f"\nExtraction failed: {e}")
        pause()


if __name__ == "__main__":
    app = StegoTUI()
    try:
        app.run()
    except KeyboardInterrupt:
        print("\nManual termination of program.")