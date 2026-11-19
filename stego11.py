import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import numpy as np
from PIL import Image, ImageTk
try:
    import cv2
except ImportError:
    cv2 = None
import wave
import struct
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import random
import hashlib

class StormCrypt:
    def __init__(self):
        self.supported_formats = {
            'image': ['.png', '.bmp'],
            'audio': ['.wav']
        }
        
    def generate_key(self, password, salt):
        """Generate AES key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_data(self, data, password):
        """Encrypt data using AES-256"""
        salt = os.urandom(16)
        key = self.generate_key(password, salt)
        iv = os.urandom(16)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Pad data to multiple of 16
        pad_len = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_len] * pad_len)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        return salt + iv + encrypted
    
    def decrypt_data(self, encrypted_data, password):
        """Decrypt data using AES-256"""
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        key = self.generate_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = decrypted[-1]
        return decrypted[:-pad_len]
    
    def embed_in_image(self, image_path, data, password=None, output_path=None):
        """Hide data in image using LSB with improved reliability"""
        try:
            print(f"Loading image: {image_path}")
            
            # Load image
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img_array = np.array(img)
            
            print(f"Image size: {img_array.shape}")
            
            # Prepare data
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Encrypt data if password provided
            if password:
                print("Encrypting data...")
                data = self.encrypt_data(data, password)
            
            # Create data packet: [4 bytes length][data][end marker]
            data_packet = len(data).to_bytes(4, 'big') + data + b'<StormCrypt_END>'
            binary_data = ''.join(format(byte, '08b') for byte in data_packet)
            
            print(f"Data to hide: {len(data)} bytes")
            print(f"Total bits needed: {len(binary_data)} bits")
            
            # Check capacity
            max_bits = img_array.shape[0] * img_array.shape[1] * 3
            if len(binary_data) > max_bits:
                raise ValueError(f"Image too small. Need {len(binary_data)} bits, have {max_bits}")
            
            # Embed data using LSB
            stego_img = img_array.copy()
            bit_index = 0
            
            for i in range(img_array.shape[0]):
                for j in range(img_array.shape[1]):
                    for k in range(3):  # RGB channels
                        if bit_index < len(binary_data):
                            # Modify LSB
                            pixel_val = stego_img[i, j, k]
                            stego_img[i, j, k] = (pixel_val & 0xFE) | int(binary_data[bit_index])
                            bit_index += 1
                        else:
                            break
                    if bit_index >= len(binary_data):
                        break
                if bit_index >= len(binary_data):
                    break
            
            print(f"Embedded {bit_index} bits successfully")
            
            # Save result
            result_img = Image.fromarray(stego_img)
            if output_path:
                result_img.save(output_path)
                print(f"Saved stego image: {output_path}")
                return output_path
            else:
                return result_img
                
        except Exception as e:
            print(f"Embedding error: {e}")
            raise Exception(f"Image embedding failed: {str(e)}")
    
    def extract_from_image(self, image_path, password=None):
        """Extract hidden data from image with improved error handling"""
        try:
            print(f"Loading stego image: {image_path}")
            
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            img_array = np.array(img)
            
            print("Extracting length header...")
            
            # Extract length header (first 32 bits)
            binary_length = ''
            bit_count = 0
            
            for i in range(img_array.shape[0]):
                for j in range(img_array.shape[1]):
                    for k in range(3):  # RGB channels
                        if bit_count < 32:
                            binary_length += str(img_array[i, j, k] & 1)
                            bit_count += 1
                        else:
                            break
                    if bit_count >= 32:
                        break
                if bit_count >= 32:
                    break
            
            # Decode length
            try:
                data_length = int(binary_length, 2)
                print(f"Data length from header: {data_length} bytes")
                
                # Sanity check
                if data_length <= 0 or data_length > 10000000:  # Max 10MB
                    raise ValueError(f"Invalid data length: {data_length}")
                    
            except ValueError as e:
                print(f"Length header error: {e}")
                return "No valid hidden data found or corrupted header"
            
            # Extract data bits
            print("Extracting data...")
            binary_data = ''
            bit_count = 0
            target_bits = data_length * 8
            
            for i in range(img_array.shape[0]):
                for j in range(img_array.shape[1]):
                    for k in range(3):
                        if bit_count < 32:
                            bit_count += 1  # Skip header
                            continue
                        elif bit_count < 32 + target_bits:
                            binary_data += str(img_array[i, j, k] & 1)
                            bit_count += 1
                        else:
                            break
                    if bit_count >= 32 + target_bits:
                        break
                if bit_count >= 32 + target_bits:
                    break
            
            # Convert binary to bytes
            extracted_bytes = bytearray()
            for i in range(0, len(binary_data), 8):
                if i + 8 <= len(binary_data):
                    byte_str = binary_data[i:i+8]
                    extracted_bytes.append(int(byte_str, 2))
            
            extracted_data = bytes(extracted_bytes)
            print(f"Extracted {len(extracted_data)} bytes")
            
            # Remove end marker
            if extracted_data.endswith(b'<StormCrypt_END>'):
                extracted_data = extracted_data[:-11]  # Remove <StormCrypt_END>
                print("End marker found and removed")
            
            # Handle decryption
            if password:
                print("Attempting decryption...")
                try:
                    decrypted = self.decrypt_data(extracted_data, password)
                    result = decrypted.decode('utf-8')
                    print("Decryption successful")
                    return result
                except Exception as e:
                    print(f"Decryption failed: {e}")
                    return f"Decryption failed - wrong password or corrupted data: {str(e)}"
            else:
                try:
                    result = extracted_data.decode('utf-8')
                    print("Direct UTF-8 decode successful")
                    return result
                except UnicodeDecodeError as e:
                    print(f"UTF-8 decode failed: {e}")
                    # Try to detect if data is encrypted
                    if len(extracted_data) > 32 and all(b > 0 for b in extracted_data[:32]):
                        return "Data appears to be encrypted - please provide the correct password"
                    else:
                        return f"Data extraction failed - corrupted or invalid format"
                
        except Exception as e:
            print(f"Extraction error: {e}")
            return f"Extraction failed: {str(e)}"

class StormCryptGUI:
    def __init__(self):
        self.StormCrypt = StormCrypt()
        self.root = tk.Tk()
        self.root.title("StormCrypt - Advanced Steganography Tool v2.0")
        self.root.geometry("900x700")
        
        # Configure style
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        
        self.setup_gui()
    
    def safe_file_dialog(self, title="Select file", filetypes=None, save_mode=False):
        """macOS-compatible file dialog"""
        try:
            if filetypes:
                # macOS-friendly format
                safe_filetypes = []
                for name, pattern in filetypes:
                    safe_pattern = pattern.replace(';', ' ')
                    safe_filetypes.append((name, safe_pattern))
            else:
                safe_filetypes = [("All files", "*")]
            
            if save_mode:
                return filedialog.asksaveasfilename(
                    title=title,
                    filetypes=safe_filetypes
                )
            else:
                return filedialog.askopenfilename(
                    title=title,
                    filetypes=safe_filetypes
                )
        except Exception as e:
            print(f"File dialog error: {e}")
            # Fallback
            if save_mode:
                return filedialog.asksaveasfilename(title=title)
            else:
                return filedialog.askopenfilename(title=title)
        
    def setup_gui(self):
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="StormCrypt - Advanced Steganography Tool", 
                               font=('Helvetica', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=(0, 20))
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Hide tab
        hide_frame = ttk.Frame(notebook, padding="10")
        notebook.add(hide_frame, text="🔒 Hide Data")
        self.setup_hide_tab(hide_frame)
        
        # Extract tab
        extract_frame = ttk.Frame(notebook, padding="10")
        notebook.add(extract_frame, text="🔓 Extract Data")
        self.setup_extract_tab(extract_frame)
        
        # Debug tab
        debug_frame = ttk.Frame(notebook, padding="10")
        notebook.add(debug_frame, text="🔧 Debug")
        self.setup_debug_tab(debug_frame)
    
    def setup_hide_tab(self, parent):
        # Configure grid
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(2, weight=1)
        
        # File selection
        ttk.Label(parent, text="1. Select Cover Image:", font=('Helvetica', 10, 'bold')).grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))
        
        self.cover_file_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.cover_file_var, width=60).grid(
            row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        ttk.Button(parent, text="Browse", command=self.browse_cover_file).grid(
            row=1, column=1, sticky=tk.W)
        
        # Data input
        ttk.Label(parent, text="2. Enter Secret Data:", font=('Helvetica', 10, 'bold')).grid(
            row=2, column=0, columnspan=2, sticky=tk.W, pady=(20, 5))
        
        # Text area with scrollbar
        text_frame = ttk.Frame(parent)
        text_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        
        self.data_text = tk.Text(text_frame, height=8, wrap=tk.WORD)
        self.data_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=self.data_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.data_text.configure(yscrollcommand=scrollbar.set)
        
        # Password
        ttk.Label(parent, text="3. Password (optional):", font=('Helvetica', 10, 'bold')).grid(
            row=4, column=0, columnspan=2, sticky=tk.W, pady=(10, 5))
        
        self.password_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.password_var, show="*", width=30).grid(
            row=5, column=0, sticky=tk.W, pady=(0, 20))
        
        # Hide button
        hide_btn = ttk.Button(parent, text="🔒 Hide Data", command=self.hide_data)
        hide_btn.grid(row=6, column=0, columnspan=2, pady=10)
        
        # Status
        self.hide_status = tk.StringVar(value="Ready to hide data")
        status_label = ttk.Label(parent, textvariable=self.hide_status, foreground="blue")
        status_label.grid(row=7, column=0, columnspan=2, pady=5)
    
    def setup_extract_tab(self, parent):
        # Configure grid
        parent.columnconfigure(1, weight=1)
        parent.rowconfigure(3, weight=1)
        
        # File selection
        ttk.Label(parent, text="1. Select Stego Image:", font=('Helvetica', 10, 'bold')).grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 5))
        
        self.stego_file_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.stego_file_var, width=60).grid(
            row=1, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        ttk.Button(parent, text="Browse", command=self.browse_stego_file).grid(
            row=1, column=1, sticky=tk.W)
        
        # Password
        ttk.Label(parent, text="2. Password (if encrypted):", font=('Helvetica', 10, 'bold')).grid(
            row=2, column=0, columnspan=2, sticky=tk.W, pady=(20, 5))
        
        self.extract_password_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.extract_password_var, show="*", width=30).grid(
            row=3, column=0, sticky=tk.W, pady=(0, 10))
        
        # Extract button
        extract_btn = ttk.Button(parent, text="🔓 Extract Data", command=self.extract_data)
        extract_btn.grid(row=4, column=0, columnspan=2, pady=10)
        
        # Results
        ttk.Label(parent, text="3. Extracted Data:", font=('Helvetica', 10, 'bold')).grid(
            row=5, column=0, columnspan=2, sticky=tk.W, pady=(20, 5))
        
        # Result text area with scrollbar
        result_frame = ttk.Frame(parent)
        result_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        
        self.result_text = tk.Text(result_frame, height=8, wrap=tk.WORD)
        self.result_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        result_scrollbar = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.result_text.yview)
        result_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.result_text.configure(yscrollcommand=result_scrollbar.set)
        
        # Copy button
        ttk.Button(parent, text="📋 Copy to Clipboard", command=self.copy_result).grid(
            row=7, column=0, pady=5, sticky=tk.W)
        
        # Status
        self.extract_status = tk.StringVar(value="Ready to extract data")
        status_label = ttk.Label(parent, textvariable=self.extract_status, foreground="blue")
        status_label.grid(row=8, column=0, columnspan=2, pady=5)
    
    def setup_debug_tab(self, parent):
        ttk.Label(parent, text="Debug Tools", font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        # Quick test section
        test_frame = ttk.LabelFrame(parent, text="Quick Test", padding="10")
        test_frame.pack(fill='x', pady=10)
        
        ttk.Button(test_frame, text="🧪 Run Basic Test", command=self.run_basic_test).pack(pady=5)
        ttk.Button(test_frame, text="🔍 Analyze Image", command=self.analyze_image).pack(pady=5)
        
        # Debug output
        ttk.Label(parent, text="Debug Output:").pack(pady=(20, 5))
        
        debug_frame = ttk.Frame(parent)
        debug_frame.pack(fill='both', expand=True)
        
        self.debug_text = tk.Text(debug_frame, height=15, wrap=tk.WORD)
        self.debug_text.pack(side='left', fill='both', expand=True)
        
        debug_scroll = ttk.Scrollbar(debug_frame, orient=tk.VERTICAL, command=self.debug_text.yview)
        debug_scroll.pack(side='right', fill='y')
        self.debug_text.configure(yscrollcommand=debug_scroll.set)
    
    def browse_cover_file(self):
        filename = self.safe_file_dialog(
            title="Select Cover Image",
            filetypes=[("PNG Images", "*.png"), ("BMP Images", "*.bmp"), ("All Images", "*.png *.bmp")]
        )
        if filename:
            self.cover_file_var.set(filename)
    
    def browse_stego_file(self):
        filename = self.safe_file_dialog(
            title="Select Stego Image",
            filetypes=[("PNG Images", "*.png"), ("BMP Images", "*.bmp"), ("All Images", "*.png *.bmp")]
        )
        if filename:
            self.stego_file_var.set(filename)
    
    def hide_data(self):
        try:
            cover_file = self.cover_file_var.get().strip()
            data = self.data_text.get("1.0", tk.END).strip()
            password = self.password_var.get().strip() if self.password_var.get().strip() else None
            
            if not cover_file:
                messagebox.showerror("Error", "Please select a cover image file")
                return
            
            if not os.path.exists(cover_file):
                messagebox.showerror("Error", "Cover image file does not exist")
                return
            
            if not data:
                messagebox.showerror("Error", "Please enter data to hide")
                return
            
            self.hide_status.set("Processing...")
            self.root.update()
            
            # Get output file
            file_ext = os.path.splitext(cover_file)[1].lower()
            output_path = self.safe_file_dialog(
                title="Save Stego Image As",
                filetypes=[("Same format", f"*{file_ext}"), ("PNG Image", "*.png")],
                save_mode=True
            )
            
            if not output_path:
                self.hide_status.set("Operation cancelled")
                return
            
            # Ensure proper extension
            if not output_path.lower().endswith(('.png', '.bmp')):
                output_path += '.png'
            
            # Hide data
            result = self.StormCrypt.embed_in_image(cover_file, data, password, output_path)
            
            self.hide_status.set(f"✅ Data hidden successfully in: {os.path.basename(output_path)}")
            messagebox.showinfo("Success", f"Data hidden successfully!\n\nOutput file: {output_path}")
            
        except Exception as e:
            error_msg = str(e)
            self.hide_status.set(f"❌ Error: {error_msg}")
            messagebox.showerror("Error", f"Failed to hide data:\n\n{error_msg}")
    
    def extract_data(self):
        try:
            stego_file = self.stego_file_var.get().strip()
            password = self.extract_password_var.get().strip() if self.extract_password_var.get().strip() else None
            
            if not stego_file:
                messagebox.showerror("Error", "Please select a stego image file")
                return
            
            if not os.path.exists(stego_file):
                messagebox.showerror("Error", "Stego image file does not exist")
                return
            
            self.extract_status.set("Extracting...")
            self.root.update()
            
            # Extract data
            extracted_data = self.StormCrypt.extract_from_image(stego_file, password)
            
            # Display result
            self.result_text.delete("1.0", tk.END)
            self.result_text.insert("1.0", extracted_data)
            
            if "failed" in extracted_data.lower() or "error" in extracted_data.lower():
                self.extract_status.set(f"❌ {extracted_data}")
            else:
                self.extract_status.set(f"✅ Data extracted successfully ({len(extracted_data)} characters)")
            
        except Exception as e:
            error_msg = str(e)
            self.extract_status.set(f"❌ Error: {error_msg}")
            messagebox.showerror("Error", f"Failed to extract data:\n\n{error_msg}")
    
    def copy_result(self):
        try:
            result = self.result_text.get("1.0", tk.END).strip()
            if result:
                self.root.clipboard_clear()
                self.root.clipboard_append(result)
                messagebox.showinfo("Copied", "Result copied to clipboard!")
            else:
                messagebox.showwarning("Warning", "No data to copy")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}")
    
    def run_basic_test(self):
        try:
            self.debug_text.delete("1.0", tk.END)
            self.debug_text.insert("1.0", "Running basic steganography test...\n\n")
            
            # Create test image
            test_img = Image.new('RGB', (200, 200), 'white')
            test_path = 'test_image.png'
            test_img.save(test_path)
            
            self.debug_text.insert(tk.END, f"✅ Created test image: {test_path}\n")
            
            # Test data
            test_data = "Hello, this is a test message from StormCrypt!"
            test_password = "test123"
            
            # Test hiding
            stego_path = 'test_stego.png'
            self.StormCrypt.embed_in_image(test_path, test_data, test_password, stego_path)
            self.debug_text.insert(tk.END, f"✅ Hidden test data in: {stego_path}\n")
            
            # Test extraction
            extracted = self.StormCrypt.extract_from_image(stego_path, test_password)
            self.debug_text.insert(tk.END, f"✅ Extracted data: {extracted}\n")
            
            # Verify
            if extracted == test_data:
                self.debug_text.insert(tk.END, "\n🎉 TEST PASSED - Steganography working correctly!\n")
            else:
                self.debug_text.insert(tk.END, f"\n❌ TEST FAILED - Expected: {test_data}\n")
            
            # Cleanup
            for f in [test_path, stego_path]:
                if os.path.exists(f):
                    os.remove(f)
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"\n❌ TEST ERROR: {str(e)}\n")
    
    def analyze_image(self):
        try:
            filename = self.safe_file_dialog(
                title="Select Image to Analyze",
                filetypes=[("Images", "*.png *.bmp")]
            )
            
            if not filename:
                return
            
            self.debug_text.delete("1.0", tk.END)
            self.debug_text.insert("1.0", f"Analyzing image: {filename}\n\n")
            
            img = Image.open(filename)
            self.debug_text.insert(tk.END, f"Image format: {img.format}\n")
            self.debug_text.insert(tk.END, f"Image mode: {img.mode}\n")
            self.debug_text.insert(tk.END, f"Image size: {img.size}\n")
            
            if img.mode == 'RGB':
                img_array = np.array(img)
                total_pixels = img_array.shape[0] * img_array.shape[1]
                total_bits = total_pixels * 3
                
                self.debug_text.insert(tk.END, f"Total pixels: {total_pixels:,}\n")
                self.debug_text.insert(tk.END, f"Available LSB bits: {total_bits:,}\n")
                self.debug_text.insert(tk.END, f"Max data capacity: ~{total_bits // 8:,} bytes\n")
                
                # Check first few LSBs for patterns
                lsbs = []
                for i in range(min(100, img_array.shape[0])):
                    for j in range(min(100, img_array.shape[1])):
                        for k in range(3):
                            lsbs.append(img_array[i, j, k] & 1)
                            if len(lsbs) >= 200:
                                break
                        if len(lsbs) >= 200:
                            break
                    if len(lsbs) >= 200:
                        break
                
                lsb_string = ''.join(map(str, lsbs[:100]))
                self.debug_text.insert(tk.END, f"\nFirst 100 LSBs: {lsb_string}\n")
                
                # Try to detect if there might be hidden data
                ones = lsbs.count(1)
                zeros = lsbs.count(0)
                ratio = ones / len(lsbs) if lsbs else 0
                
                self.debug_text.insert(tk.END, f"LSB distribution - 1s: {ones}, 0s: {zeros}\n")
                self.debug_text.insert(tk.END, f"Ratio of 1s: {ratio:.3f}\n")
                
                if 0.4 < ratio < 0.6:
                    self.debug_text.insert(tk.END, "📊 LSB distribution looks random (might contain data)\n")
                else:
                    self.debug_text.insert(tk.END, "📊 LSB distribution appears non-random\n")
            
        except Exception as e:
            self.debug_text.insert(tk.END, f"❌ Analysis error: {str(e)}\n")
    
    def run(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            print("Application interrupted by user")
        except Exception as e:
            print(f"GUI Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="StormCrypt - Advanced Steganography Tool")
    parser.add_argument("--mode", choices=['gui', 'hide', 'extract', 'test'], default='gui',
                       help="Operation mode")
    parser.add_argument("--cover", help="Cover file path")
    parser.add_argument("--stego", help="Stego file path")
    parser.add_argument("--data", help="Data to hide")
    parser.add_argument("--output", help="Output file path")
    parser.add_argument("--password", help="Encryption password")
    
    args = parser.parse_args()
    
    if args.mode == 'gui':
        print("Launching StormCrypt GUI...")
        app = StormCryptGUI()
        app.run()
    
    elif args.mode == 'hide':
        if not args.cover or not args.data:
            print("Error: --cover and --data are required for hide mode")
            print("Example: python StormCrypt.py --mode hide --cover image.png --data 'secret message' --output hidden.png")
            return
        
        StormCrypt = StormCrypt()
        try:
            output = args.output or f"stego_{os.path.basename(args.cover)}"
            print(f"Hiding data in {args.cover}...")
            result = StormCrypt.embed_in_image(args.cover, args.data, args.password, output)
            print(f"✅ Data hidden successfully in: {result}")
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif args.mode == 'extract':
        if not args.stego:
            print("Error: --stego is required for extract mode")
            print("Example: python StormCrypt.py --mode extract --stego hidden.png --password mypass")
            return
        
        StormCrypt = StormCrypt()
        try:
            print(f"Extracting data from {args.stego}...")
            extracted = StormCrypt.extract_from_image(args.stego, args.password)
            print("\n" + "="*50)
            print("EXTRACTED DATA:")
            print("="*50)
            print(extracted)
            print("="*50)
            
        except Exception as e:
            print(f"❌ Error: {str(e)}")
    
    elif args.mode == 'test':
        print("Running comprehensive test...")
        StormCrypt = StormCrypt()
        try:
            # Create test image
            test_img = Image.new('RGB', (100, 100), 'red')
            test_img.save('test_cover.png')
            print("✅ Created test cover image")
            
            # Test without password
            test_data = "Hello World! This is a test message."
            StormCrypt.embed_in_image('test_cover.png', test_data, None, 'test_stego1.png')
            extracted1 = StormCrypt.extract_from_image('test_stego1.png', None)
            print(f"✅ Test 1 (no password): {'PASS' if extracted1 == test_data else 'FAIL'}")
            
            # Test with password
            test_password = "secret123"
            StormCrypt.embed_in_image('test_cover.png', test_data, test_password, 'test_stego2.png')
            extracted2 = StormCrypt.extract_from_image('test_stego2.png', test_password)
            print(f"✅ Test 2 (with password): {'PASS' if extracted2 == test_data else 'FAIL'}")
            
            # Cleanup
            for f in ['test_cover.png', 'test_stego1.png', 'test_stego2.png']:
                if os.path.exists(f):
                    os.remove(f)
            
            print("🎉 All tests completed!")
            
        except Exception as e:
            print(f"❌ Test failed: {str(e)}")

if __name__ == "__main__":
    main()
