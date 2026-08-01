import sys
import os
import struct
import math
import zlib  # Data compression before encryption
from pathlib import Path

import numpy as np
from PIL import Image

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QLabel, QLineEdit, QTextEdit, QPushButton, QFileDialog,
    QListWidget, QMessageBox, QProgressBar, QGroupBox, QCheckBox,
    QRadioButton, QButtonGroup, QStackedWidget
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt

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
# SPATIAL STEGANOGRAPHY (LSB across ALL RGB channels to maximize compactness)
# -------------------------------------------------------------------

def image_capacity_bytes(image_path: str) -> int:
    with Image.open(image_path) as img:
        w, h = img.size
    # Capacity is tripled because we use R, G, and B channels
    total_bits = w * h * 3
    return max(0, total_bits // 8 - CHUNK_HEADER_SIZE)


def embed_chunk(cover_path: str, output_path: str, chunk_bytes: bytes,
                 chunk_index: int, total_chunks: int):
    header = struct.pack(CHUNK_HEADER_FMT, MAGIC, total_chunks, chunk_index, len(chunk_bytes))
    payload = header + chunk_bytes
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    num_bits = len(bits)

    img = Image.open(cover_path).convert("RGB")
    w, h = img.size

    # AUTOMATIC RESIZING (adjusted for RGB capacity)
    if num_bits > w * h * 3:
        scale = math.sqrt(num_bits / (w * h * 3))
        new_w = int(math.ceil(w * scale))
        new_h = int(math.ceil(h * scale))
        
        while new_w * new_h * 3 < num_bits:
            new_w += 1
            new_h += 1
            
        img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)

    img_np = np.array(img, dtype=np.uint8)
    
    # Flatten the entire image (R, G, B combined)
    flat_img = img_np.flatten()

    flat_img[:num_bits] = (flat_img[:num_bits] & 0xFE) | bits
    img_np = flat_img.reshape(img_np.shape)

    stego_img = Image.fromarray(img_np)
    # 'optimize=True' helps slightly reduce the final PNG footprint
    stego_img.save(output_path, format="PNG", optimize=True)


def extract_chunk(stego_path: str) -> tuple[int, int, bytes]:
    img = Image.open(stego_path).convert("RGB")
    img_np = np.array(img, dtype=np.uint8)
    
    # Global flattening of the image (R, G, B)
    flat_img = img_np.flatten()

    header_bit_count = CHUNK_HEADER_SIZE * 8
    if flat_img.size < header_bit_count:
        raise ValueError(f"Image '{os.path.basename(stego_path)}' is too small to contain a valid header.")

    header_bits = flat_img[:header_bit_count] & 1
    header_bytes = np.packbits(header_bits).tobytes()

    magic, total_chunks, chunk_index, chunk_len = struct.unpack(CHUNK_HEADER_FMT, header_bytes)
    if magic != MAGIC:
        raise ValueError(f"Image '{os.path.basename(stego_path)}' does not contain valid steganographic data.")

    total_bits = (CHUNK_HEADER_SIZE + chunk_len) * 8
    if total_bits > flat_img.size:
        raise ValueError(f"Image '{os.path.basename(stego_path)}' appears corrupted or truncated.")

    payload_bits = flat_img[:total_bits] & 1
    payload_bytes = np.packbits(payload_bits).tobytes()

    return chunk_index, total_chunks, payload_bytes[CHUNK_HEADER_SIZE:]

# -------------------------------------------------------------------
# WORKER THREADS
# -------------------------------------------------------------------

class EmbedWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, cover_images, output_dir, secret_bytes, filename, password):
        super().__init__()
        self.cover_images = cover_images
        self.output_dir = output_dir
        self.secret_bytes = secret_bytes
        self.filename = filename
        self.password = password

    def run(self):
        try:
            num_images = len(self.cover_images)
            if num_images > MAX_CHUNKS:
                raise ValueError(f"Too many images selected (max {MAX_CHUNKS}).")

            raw_payload = build_payload(self.secret_bytes, self.filename)
            
            # 1. Maximum compression (zlib)
            compressed_payload = zlib.compress(raw_payload, level=9)
            
            # 2. AES-256 GCM encryption of compressed data
            encrypted_payload = encrypt_data(compressed_payload, self.password)
            chunks = np.array_split(np.frombuffer(encrypted_payload, dtype=np.uint8), num_images)

            os.makedirs(self.output_dir, exist_ok=True)

            for i, cover_path in enumerate(self.cover_images):
                chunk_bytes = chunks[i].tobytes()
                out_path = os.path.join(self.output_dir, f"stego_part_{i + 1:02d}.png")
                embed_chunk(cover_path, out_path, chunk_bytes, chunk_index=i, total_chunks=num_images)
                self.progress.emit(int(((i + 1) / num_images) * 100))

            kind = "file" if self.filename else "text"
            self.finished.emit(f"Data ({kind}) encrypted, compressed, and hidden in {num_images} image(s):\n{self.output_dir}")
        except Exception as e:
            self.error.emit(str(e))


class ExtractWorker(QThread):
    progress = pyqtSignal(int)
    finished = pyqtSignal(object) 
    error = pyqtSignal(str)

    def __init__(self, stego_images, password):
        super().__init__()
        self.stego_images = stego_images
        self.password = password

    def run(self):
        try:
            found = {}
            expected_total = None
            n = len(self.stego_images)

            for i, stego_path in enumerate(self.stego_images):
                chunk_index, total_chunks, chunk_bytes = extract_chunk(stego_path)

                if expected_total is None:
                    expected_total = total_chunks
                elif total_chunks != expected_total:
                    raise ValueError(
                        "Selected images do not belong to the same set "
                        f"(mismatch detected in '{os.path.basename(stego_path)}')."
                    )

                if chunk_index in found:
                    raise ValueError(f"Duplicate chunk {chunk_index} (file '{os.path.basename(stego_path)}').")

                found[chunk_index] = chunk_bytes
                self.progress.emit(int(((i + 1) / n) * 100))

            if expected_total is None or len(found) != expected_total:
                missing = sorted(set(range(expected_total or 0)) - set(found.keys()))
                raise ValueError(
                    f"Missing {len(missing)} chunk(s) out of {expected_total} expected. "
                    "Select all images from the original set."
                )

            full_payload = b"".join(found[i] for i in range(expected_total))
            
            # 1. AES Decryption
            decrypted_compressed = decrypt_data(full_payload, self.password)
            
            # 2. zlib Decompression
            try:
                decrypted_raw = zlib.decompress(decrypted_compressed)
            except zlib.error:
                raise ValueError("Decompression failed: corrupted data or incorrect password.")
                
            is_file, filename, data = parse_payload(decrypted_raw)
            self.finished.emit((is_file, filename, data))
        except UnicodeDecodeError:
            self.error.emit("Decryption failed: incorrect password or corrupted data.")
        except Exception as e:
            self.error.emit(f"Decryption failed.\n\nDetail: {str(e)}")

# -------------------------------------------------------------------
# GRAPHICAL USER INTERFACE
# -------------------------------------------------------------------

class StegoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PHOTOCRYPT GUI 0.01 - Hide and Encrypt Data in Images")
        self.resize(760, 700)
        self.embed_worker = None
        self.extract_worker = None
        self.selected_file_path = None
        self.last_extracted_filename = None
        self.last_extracted_bytes = None
        self.init_ui()

    def init_ui(self):
        tabs = QTabWidget()
        tabs.addTab(self.create_embed_tab(), "Embed")
        tabs.addTab(self.create_extract_tab(), "Extract")
        self.setCentralWidget(tabs)

    def create_embed_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        gb_files = QGroupBox("1. Select source images")
        layout_files = QVBoxLayout(gb_files)

        self.list_embed_images = QListWidget()
        btn_add_files = QPushButton("Add images...")
        btn_add_files.clicked.connect(self.select_embed_images)
        btn_clear_files = QPushButton("Clear")
        btn_clear_files.clicked.connect(self.list_embed_images.clear)

        h_btn_layout = QHBoxLayout()
        h_btn_layout.addWidget(btn_add_files)
        h_btn_layout.addWidget(btn_clear_files)

        self.label_capacity = QLabel("Total capacity: —")

        layout_files.addWidget(self.list_embed_images)
        layout_files.addLayout(h_btn_layout)
        layout_files.addWidget(self.label_capacity)
        layout.addWidget(gb_files)

        gb_secret = QGroupBox("2. Data to hide")
        layout_secret = QVBoxLayout(gb_secret)

        self.radio_mode_text = QRadioButton("Text")
        self.radio_mode_file = QRadioButton("File (any type)")
        self.radio_mode_text.setChecked(True)
        self.mode_group = QButtonGroup(self)
        self.mode_group.addButton(self.radio_mode_text)
        self.mode_group.addButton(self.radio_mode_file)

        h_mode = QHBoxLayout()
        h_mode.addWidget(self.radio_mode_text)
        h_mode.addWidget(self.radio_mode_file)
        layout_secret.addLayout(h_mode)

        self.stack_mode = QStackedWidget()

        page_text = QWidget()
        v_text = QVBoxLayout(page_text)
        v_text.setContentsMargins(0, 0, 0, 0)
        self.text_embed_secret = QTextEdit()
        self.text_embed_secret.setPlaceholderText("Enter the text to hide...")
        self.text_embed_secret.textChanged.connect(self.update_capacity_label)
        v_text.addWidget(self.text_embed_secret)
        self.stack_mode.addWidget(page_text)

        page_file = QWidget()
        v_file = QVBoxLayout(page_file)
        v_file.setContentsMargins(0, 0, 0, 0)
        self.label_selected_file = QLabel("No file selected.")
        self.label_selected_file.setWordWrap(True)
        btn_choose_file = QPushButton("Choose a file...")
        btn_choose_file.clicked.connect(self.select_secret_file)
        v_file.addWidget(btn_choose_file)
        v_file.addWidget(self.label_selected_file)
        v_file.addStretch()
        self.stack_mode.addWidget(page_file)

        layout_secret.addWidget(self.stack_mode)

        self.radio_mode_text.toggled.connect(self.on_mode_toggled)
        layout.addWidget(gb_secret)

        gb_pass = QGroupBox("3. Password")
        layout_pass = QVBoxLayout(gb_pass)

        self.input_embed_pass = QLineEdit()
        self.input_embed_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_embed_pass.setPlaceholderText("AES-256 Password")

        self.input_embed_pass_confirm = QLineEdit()
        self.input_embed_pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_embed_pass_confirm.setPlaceholderText("Confirm Password")

        self.chk_show_pass = QCheckBox("Show passwords")
        self.chk_show_pass.stateChanged.connect(self.toggle_password_visibility)

        layout_pass.addWidget(QLabel("Password:"))
        layout_pass.addWidget(self.input_embed_pass)
        layout_pass.addWidget(QLabel("Confirmation:"))
        layout_pass.addWidget(self.input_embed_pass_confirm)
        layout_pass.addWidget(self.chk_show_pass)
        layout.addWidget(gb_pass)

        self.progress_embed = QProgressBar()
        self.btn_run_embed = QPushButton("Generate stego image set")
        self.btn_run_embed.clicked.connect(self.run_embedding)

        layout.addWidget(self.progress_embed)
        layout.addWidget(self.btn_run_embed)
        return widget

    def on_mode_toggled(self, checked_text_mode):
        self.stack_mode.setCurrentIndex(0 if checked_text_mode else 1)
        self.update_capacity_label()

    def toggle_password_visibility(self, state):
        mode = QLineEdit.EchoMode.Normal if state == Qt.CheckState.Checked.value else QLineEdit.EchoMode.Password
        self.input_embed_pass.setEchoMode(mode)
        self.input_embed_pass_confirm.setEchoMode(mode)

    def select_embed_images(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select images", "", "Images (*.png *.jpg *.jpeg *.bmp)")
        if files:
            self.list_embed_images.addItems(files)
            self.update_capacity_label()

    def select_secret_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose file to hide", "", "All Files (*)")
        if path:
            self.selected_file_path = path
            size = os.path.getsize(path)
            self.label_selected_file.setText(f"{os.path.basename(path)} ({size} bytes)")
            self.update_capacity_label()

    def update_capacity_label(self):
        count = self.list_embed_images.count()
        if count == 0:
            self.label_capacity.setText("Total capacity: —")
            return
        try:
            total_capacity = sum(
                image_capacity_bytes(self.list_embed_images.item(i).text()) for i in range(count)
            )
        except Exception:
            self.label_capacity.setText("Total capacity: (error reading an image)")
            return

        if self.radio_mode_file.isChecked():
            raw_size = os.path.getsize(self.selected_file_path) if self.selected_file_path else 0
            name_len = len(os.path.basename(self.selected_file_path).encode("utf-8")) if self.selected_file_path else 0
        else:
            raw_size = len(self.text_embed_secret.toPlainText().encode("utf-8"))
            name_len = 0

        needed = raw_size + name_len + PAYLOAD_HEADER_SIZE + 44 + count * CHUNK_HEADER_SIZE
        status = "OK" if needed <= total_capacity else "Auto-resizing"
        self.label_capacity.setText(
            f"Base capacity: {total_capacity} bytes — estimated need: {needed} bytes [{status}]"
        )

    def run_embedding(self):
        count = self.list_embed_images.count()
        if count == 0:
            QMessageBox.warning(self, "Warning", "Please add at least one image.")
            return

        is_file_mode = self.radio_mode_file.isChecked()

        if is_file_mode:
            if not self.selected_file_path:
                QMessageBox.warning(self, "Warning", "Please choose a file to hide.")
                return
            try:
                with open(self.selected_file_path, "rb") as f:
                    secret_bytes = f.read()
            except OSError as e:
                QMessageBox.critical(self, "Error", f"Unable to read file:\n{e}")
                return
            filename = os.path.basename(self.selected_file_path)
            if not secret_bytes:
                QMessageBox.warning(self, "Warning", "The selected file is empty.")
                return
        else:
            secret_text = self.text_embed_secret.toPlainText().strip()
            if not secret_text:
                QMessageBox.warning(self, "Warning", "Text is required.")
                return
            secret_bytes = secret_text.encode("utf-8")
            filename = None

        password = self.input_embed_pass.text()
        password_confirm = self.input_embed_pass_confirm.text()

        if not password:
            QMessageBox.warning(self, "Warning", "Password is required.")
            return

        if password != password_confirm:
            QMessageBox.warning(self, "Warning", "Passwords do not match.")
            return

        if count > MAX_CHUNKS:
            QMessageBox.warning(self, "Warning", f"Too many images selected (maximum {MAX_CHUNKS}).")
            return

        out_dir = QFileDialog.getExistingDirectory(self, "Output directory for stego images")
        if not out_dir:
            return

        cover_paths = [self.list_embed_images.item(i).text() for i in range(count)]

        self.btn_run_embed.setEnabled(False)
        self.progress_embed.setValue(0)

        self.embed_worker = EmbedWorker(cover_paths, out_dir, secret_bytes, filename, password)
        self.embed_worker.progress.connect(self.progress_embed.setValue)
        self.embed_worker.finished.connect(self.on_embed_finished)
        self.embed_worker.error.connect(self.on_worker_error)
        self.embed_worker.start()

    def on_embed_finished(self, msg):
        self.btn_run_embed.setEnabled(True)
        QMessageBox.information(self, "Success", msg)

    def create_extract_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)

        gb_files = QGroupBox("1. Select ALL stego images from the set (.png)")
        layout_files = QVBoxLayout(gb_files)

        self.list_extract_images = QListWidget()
        btn_add_stego = QPushButton("Add stego images...")
        btn_add_stego.clicked.connect(self.select_extract_images)
        btn_clear_stego = QPushButton("Clear")
        btn_clear_stego.clicked.connect(self.list_extract_images.clear)

        h_btn_layout = QHBoxLayout()
        h_btn_layout.addWidget(btn_add_stego)
        h_btn_layout.addWidget(btn_clear_stego)

        layout_files.addWidget(self.list_extract_images)
        layout_files.addLayout(h_btn_layout)
        layout.addWidget(gb_files)

        gb_decrypt = QGroupBox("2. Password and result")
        layout_decrypt = QVBoxLayout(gb_decrypt)

        self.input_extract_pass = QLineEdit()
        self.input_extract_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.input_extract_pass.setPlaceholderText("Decryption password")

        self.chk_show_pass_extract = QCheckBox("Show password")
        self.chk_show_pass_extract.stateChanged.connect(
            lambda state: self.input_extract_pass.setEchoMode(
                QLineEdit.EchoMode.Normal if state == Qt.CheckState.Checked.value else QLineEdit.EchoMode.Password
            )
        )

        self.text_extracted_output = QTextEdit()
        self.text_extracted_output.setReadOnly(True)

        h_result_btns = QHBoxLayout()
        self.btn_copy = QPushButton("Copy result (text)")
        self.btn_copy.clicked.connect(self.copy_extracted_text)
        self.btn_save_file = QPushButton("Save extracted file...")
        self.btn_save_file.clicked.connect(self.save_extracted_file)
        self.btn_save_file.setEnabled(False)
        h_result_btns.addWidget(self.btn_copy)
        h_result_btns.addWidget(self.btn_save_file)

        layout_decrypt.addWidget(QLabel("Password:"))
        layout_decrypt.addWidget(self.input_extract_pass)
        layout_decrypt.addWidget(self.chk_show_pass_extract)
        layout_decrypt.addWidget(QLabel("Result:"))
        layout_decrypt.addWidget(self.text_extracted_output)
        layout_decrypt.addLayout(h_result_btns)
        layout.addWidget(gb_decrypt)

        self.progress_extract = QProgressBar()
        self.btn_run_extract = QPushButton("Decrypt data")
        self.btn_run_extract.clicked.connect(self.run_extraction)

        layout.addWidget(self.progress_extract)
        layout.addWidget(self.btn_run_extract)
        return widget

    def select_extract_images(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select stego images", "", "PNG Images (*.png)")
        if files:
            self.list_extract_images.addItems(files)

    def copy_extracted_text(self):
        text = self.text_extracted_output.toPlainText()
        if text:
            QApplication.clipboard().setText(text)

    def save_extracted_file(self):
        if self.last_extracted_bytes is None:
            return
        suggested_name = self.last_extracted_filename or "extracted_file.bin"
        path, _ = QFileDialog.getSaveFileName(self, "Save extracted file", suggested_name)
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self.last_extracted_bytes)
            QMessageBox.information(self, "Success", f"File saved:\n{path}")
        except OSError as e:
            QMessageBox.critical(self, "Error", f"Unable to write file:\n{e}")

    def run_extraction(self):
        count = self.list_extract_images.count()
        if count == 0:
            QMessageBox.warning(self, "Warning", "Please select the stego images to decrypt.")
            return

        password = self.input_extract_pass.text()
        if not password:
            QMessageBox.warning(self, "Warning", "Password is required.")
            return

        stego_paths = [self.list_extract_images.item(i).text() for i in range(count)]

        self.btn_run_extract.setEnabled(False)
        self.btn_save_file.setEnabled(False)
        self.progress_extract.setValue(0)
        self.text_extracted_output.clear()
        self.last_extracted_filename = None
        self.last_extracted_bytes = None

        self.extract_worker = ExtractWorker(stego_paths, password)
        self.extract_worker.progress.connect(self.progress_extract.setValue)
        self.extract_worker.finished.connect(self.on_extract_finished)
        self.extract_worker.error.connect(self.on_worker_error)
        self.extract_worker.start()

    def on_extract_finished(self, result):
        is_file, filename, data = result
        self.btn_run_extract.setEnabled(True)

        if is_file:
            self.last_extracted_filename = filename
            self.last_extracted_bytes = data
            self.btn_save_file.setEnabled(True)
            self.text_extracted_output.setText(
                f"File detected: {filename}\nSize: {len(data)} bytes\n\n"
                'Click "Save extracted file..." to save it to disk.'
            )
            QMessageBox.information(self, "Success", f"File '{filename}' extracted and decrypted successfully!")
        else:
            try:
                decrypted_text = data.decode("utf-8")
            except UnicodeDecodeError:
                self.on_worker_error("Text decoding failed: incorrect password or corrupted data.")
                return
            self.text_extracted_output.setText(decrypted_text)
            QMessageBox.information(self, "Success", "Secret message decrypted successfully!")

    def on_worker_error(self, err_msg):
        self.btn_run_embed.setEnabled(True)
        self.btn_run_extract.setEnabled(True)
        QMessageBox.critical(self, "Error", err_msg)

    def closeEvent(self, event):
        for worker in (self.embed_worker, self.extract_worker):
            if worker is not None and worker.isRunning():
                worker.wait(2000)
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = StegoApp()
    window.show()
    sys.exit(app.exec())