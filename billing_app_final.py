import os
import random
import re
import socket
import traceback
import logging
import io
import json
import base64
from datetime import datetime
from typing import List, Tuple
from PIL import Image as PILImage, ImageDraw, ImageFont
import qrcode  
import requests
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen, SlideTransition
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner
from kivy.uix.button import Button
from kivy.uix.anchorlayout import AnchorLayout
from kivy.uix.popup import Popup
from kivy.uix.scrollview import ScrollView
from kivy.uix.checkbox import CheckBox
from kivy.graphics import Color, RoundedRectangle, Rectangle
from kivy.clock import Clock
from kivy.properties import BooleanProperty, StringProperty
from kivy.core.window import Window
from kivy.uix.widget import Widget
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='billing_app_errors.log'
)
logger = logging.getLogger(__name__)

os.environ['KIVY_NO_CONSOLELOG'] = '1'
os.environ['KIVY_NO_MULTITOUCH'] = '1'

from kivy.config import Config
Config.set('input', 'mouse', 'mouse,multitouch_on_demand')


API_BASE = "http://127.0.0.1:8000/api"
LOGO_FILENAME = r"D:\DjangoProjects\clothing_api\eleven7.jpg"


PRINTER_MAC = "10:23:81:69:D8:50"
PRINTER_PORT = 1
UPI_ID = "ravirajvibhute09@okicici" 


VALID_MOBILE_REGEX = re.compile(r'^[6-9]\d{9}$')
VALID_EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
VALID_BILL_NO_REGEX = re.compile(r'^\d{4,10}$')
VALID_NAME_REGEX = re.compile(r'^[a-zA-Z\s]{2,50}$')
VALID_PRICE_REGEX = re.compile(r'^\d+(\.\d{1,2})?$')
VALID_QUANTITY_REGEX = re.compile(r'^\d+$')


# Encryption setup for secure password storage
class CredentialsManager:
    def __init__(self):
        self.key_file = "app_key.key"
        self.creds_file = "saved_creds.dat"
        self.key = None
        self.cipher = None
        
    def generate_key(self):
        """Generate a new encryption key"""
        key = Fernet.generate_key()
        with open(self.key_file, 'wb') as f:
            f.write(key)
        return key
    
    def load_or_create_key(self):
        """Load existing key or create a new one"""
        try:
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    self.key = f.read()
            else:
                self.key = self.generate_key()
            
            self.cipher = Fernet(self.key)
            return True
        except Exception as e:
            logger.error(f"Key load/create failed: {str(e)}")
            return False
    
    def encrypt_data(self, data):
        """Encrypt data"""
        try:
            if not self.cipher:
                if not self.load_or_create_key():
                    return None
            encrypted = self.cipher.encrypt(data.encode())
            return encrypted
        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            return None
    
    def decrypt_data(self, encrypted_data):
        """Decrypt data"""
        try:
            if not self.cipher:
                if not self.load_or_create_key():
                    return None
            decrypted = self.cipher.decrypt(encrypted_data).decode()
            return decrypted
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            return None
    
    def save_credentials(self, username, password):
        """Save encrypted credentials"""
        try:
            if not self.load_or_create_key():
                return False
            
            # Create credentials dictionary
            creds = {
                'username': username,
                'password': password,
                'timestamp': datetime.now().isoformat()
            }
            
            # Convert to JSON and encrypt
            creds_json = json.dumps(creds)
            encrypted_creds = self.encrypt_data(creds_json)
            
            if encrypted_creds:
                with open(self.creds_file, 'wb') as f:
                    f.write(encrypted_creds)
                return True
            return False
        except Exception as e:
            logger.error(f"Save credentials failed: {str(e)}")
            return False
    
    def load_credentials(self):
        """Load and decrypt saved credentials"""
        try:
            if not os.path.exists(self.creds_file):
                return None, None
            
            if not self.load_or_create_key():
                return None, None
            
            with open(self.creds_file, 'rb') as f:
                encrypted_creds = f.read()
            
            decrypted_json = self.decrypt_data(encrypted_creds)
            if not decrypted_json:
                return None, None
            
            creds = json.loads(decrypted_json)
            return creds.get('username'), creds.get('password')
        except Exception as e:
            logger.error(f"Load credentials failed: {str(e)}")
            return None, None
    
    def delete_credentials(self):
        """Delete saved credentials"""
        try:
            if os.path.exists(self.creds_file):
                os.remove(self.creds_file)
                return True
            return False
        except Exception as e:
            logger.error(f"Delete credentials failed: {str(e)}")
            return False

# Global credentials manager
credentials_manager = CredentialsManager()


def validate_mobile_number(mobile: str) -> Tuple[bool, str]:
    """Validate Indian mobile number"""
    if not mobile:
        return False, "Mobile number is required"
    mobile = mobile.strip()
    if not VALID_MOBILE_REGEX.match(mobile):
        return False, "Invalid mobile number. Must be 10 digits starting with 6-9"
    return True, ""

def validate_email(email: str) -> Tuple[bool, str]:
    """Validate email address (optional)"""
    if not email or email.strip() == "":
        return True, "" 
    email = email.strip()
    if not VALID_EMAIL_REGEX.match(email):
        return False, "Invalid email format"
    return True, ""

def validate_name(name: str) -> Tuple[bool, str]:
    """Validate customer name"""
    if not name or name.strip() == "":
        return False, "Customer name is required"
    name = name.strip()
    if not VALID_NAME_REGEX.match(name):
        return False, "Invalid name. Use 2-50 characters (letters and spaces only)"
    return True, ""

def validate_price(price: str) -> Tuple[bool, str]:
    """Validate price"""
    if not price or price.strip() == "":
        return False, "Price is required"
    price = price.strip()
    if not VALID_PRICE_REGEX.match(price):
        return False, "Invalid price format. Use numbers only (e.g., 100 or 100.50)"
    try:
        price_float = float(price)
        if price_float < 0:
            return False, "Price cannot be negative"
        if price_float > 100000:
            return False, "Price is too high"
        return True, ""
    except ValueError:
        return False, "Invalid price value"

def validate_quantity(qty: str) -> Tuple[bool, str]:
    """Validate quantity"""
    if not qty or qty.strip() == "":
        return False, "Quantity is required"
    qty = qty.strip()
    if not VALID_QUANTITY_REGEX.match(qty):
        return False, "Invalid quantity. Use whole numbers only"
    try:
        qty_int = int(qty)
        if qty_int <= 0:
            return False, "Quantity must be greater than 0"
        if qty_int > 999:
            return False, "Quantity is too high (max 999)"
        return True, ""
    except ValueError:
        return False, "Invalid quantity value"

def validate_bill_no(bill_no: str) -> Tuple[bool, str]:
    """Validate bill number"""
    if not bill_no or bill_no.strip() == "":
        return False, "Bill number is required"
    bill_no = bill_no.strip()
    if not VALID_BILL_NO_REGEX.match(bill_no):
        return False, "Invalid bill number. Use 4-10 digits"
    return True, ""



def connect_to_printer() -> socket.socket:
    """Connect to Bluetooth printer using socket with validation"""
    try:
        if not PRINTER_MAC or not PRINTER_PORT:
            raise ValueError("Printer MAC address or port not configured")
        
        print(" Attempting to connect to printer...")
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        sock.settimeout(4) #printer searching timing
        
        
        if not re.match(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', PRINTER_MAC):
            raise ValueError(f"Invalid MAC address format: {PRINTER_MAC}")
        
        sock.connect((PRINTER_MAC, PRINTER_PORT))
        print(" Bill Print successfully ")
        return sock
    except socket.timeout:
        raise RuntimeError("Printer connection timeout. Check if printer is turned on and in range.")
    except socket.error as e:
        if e.errno == 111:  
            raise RuntimeError("Printer connection refused. Make sure printer is paired and ready.")
        elif e.errno == 112:  
            raise RuntimeError("Printer is unreachable. Check Bluetooth connection.")
        else:
            raise RuntimeError(f"Bluetooth connection error: {str(e)}")
    except ValueError as e:
        raise RuntimeError(f"Configuration error: {str(e)}")
    except Exception as e:
        logger.error(f"Printer connection failed: {str(e)}")
        raise RuntimeError(f"Failed to connect to printer: {str(e)}")

def generate_upi_qr_code(amount: float, bill_no: str) -> PILImage.Image:
    try:
        if amount <= 0:
            raise ValueError("Amount must be greater than 0")
        
        if not bill_no or len(bill_no.strip()) < 4:
            raise ValueError("Invalid bill number for QR code")
        
        if not UPI_ID or '@' not in UPI_ID:
            raise ValueError("Invalid UPI ID configuration")
        
        upi_url = f"upi://pay?pa={UPI_ID}&pn=ELEVEN-7&am={amount:.2f}&tn=Bill{bill_no}&cu=INR"
        
        if len(upi_url) > 256:
            raise ValueError("UPI URL too long")
        
        qr = qrcode.QRCode(
            version=6,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=2,
        )
        qr.add_data(upi_url)
        qr.make(fit=True)
        
        qr_img = qr.make_image(fill_color="black", back_color="white")
        return qr_img
    except qrcode.exceptions.DataOverflowError:
        raise RuntimeError("QR code data too large. Try reducing bill details.")
    except Exception as e:
        logger.error(f"QR code generation failed: {str(e)}")
        raise RuntimeError(f"Failed to generate QR code: {str(e)}")

def image_to_escpos_bytes(img: PILImage.Image) -> bytes:
    try:
        if not img:
            raise ValueError("Invalid image provided")
        
        if img.mode != "1":
            bw = img.convert("1")
        else:
            bw = img
            
        width, height = bw.width, bw.height
        if width > 576:
            raise ValueError(f"Image width {width} exceeds printer limit of 576px")
        if height > 2000:  
            raise ValueError(f"Image height {height} is too large")
        
        data = bytearray()
        data += b'\x1B\x40'  
        data += b'\x1D\x76\x30\x00'  

        width_bytes = (width + 7) // 8
        data += bytes([
            width_bytes % 256,
            width_bytes // 256,
            height % 256,
            height // 256
        ])

        pixels = bw.load()
        for y in range(height):
            for x in range(0, width, 8):
                byte = 0
                for bit in range(8):
                    if x + bit < width:
                        if pixels[x + bit, y] == 0:
                            byte |= 1 << (7 - bit)
                data.append(byte)

        data += b'\n\n\n\x1B\x61\x00' 
        return bytes(data)
    except Exception as e:
        logger.error(f"Image to ESC/POS conversion failed: {str(e)}")
        raise RuntimeError(f"Failed to convert image for printing: {str(e)}")


def print_with_qr_code(bill_no: str, customer_name: str, mobile: str, 
                      items: List[Tuple[str, int, float, float]], total_amount: float) -> bool:
    sock = None
    try:
        if not bill_no or not customer_name or not mobile:
            raise ValueError("Missing required bill information")
        
        if not items or len(items) == 0:
            raise ValueError("No items to print")
        
        if total_amount <= 0:
            raise ValueError("Invalid total amount")
        mobile_valid, mobile_msg = validate_mobile_number(mobile)
        if not mobile_valid:
            raise ValueError(f"Invalid mobile: {mobile_msg}")
        
        sock = connect_to_printer()
        print("Printing receipt with QR code...")
         
        sock.send(b'\x1B\x40')
        sock.send(b'\x1B\x61\x01')  
        sock.send(b'\x1B\x21\x30')  
        sock.send(b"ELEVEN-7\n")
        sock.send(b'\x1B\x21\x00')  
        sock.send(b"THE MEN'S WEAR\n")
        sock.send(b"----------------------------\n")
        
        # Store info
        sock.send(b"Panhala-Kolhapur Road\n")
        sock.send(b"Kerle, Kolhapur\n")
        sock.send(b"Phone: 9923234918\n")
        sock.send(b"----------------------------\n")
        
        # Bill details
        sock.send(b'\x1B\x61\x00')  
        sock.send(f"Bill No: {bill_no}\n".encode('utf-8'))
        sock.send(f"Date: {datetime.now().strftime('%d-%m-%Y %H:%M')}\n".encode('utf-8'))
        sock.send(f"Customer: {customer_name}\n".encode('utf-8'))
        sock.send(f"Mobile: {mobile}\n".encode('utf-8'))
        sock.send(b"----------------------------\n")
        
        # Items header
        sock.send(b'\x1B\x45\x01') 
        sock.send(f"{'ITEM':<20} {'QTY':>3} {'AMOUNT':>9}\n".encode('utf-8'))
        sock.send(b'\x1B\x45\x00') 
        sock.send(b"----------------------------\n")
        
        # Items
        for name, qty, price, line_total in items:
            display_name = name[:18] + ".." if len(name) > 20 else name
            line = f"{display_name:<20} {qty:>3} {line_total:>9.1f}\n"
            sock.send(line.encode('utf-8'))
        
        sock.send(b"----------------------------\n")
        
        # Total
        sock.send(b'\x1B\x45\x01') 
        sock.send(f"{'TOTAL:':<23} ₹{total_amount:>8.1f}\n".encode('utf-8'))
        sock.send(b'\x1B\x45\x00') 
        
        sock.send(b"============================\n\n")
        
        # QR Code Section
        sock.send(b'\x1B\x61\x01')  
        sock.send(b"SCAN & PAY\n")
        sock.send(b"UPI PAYMENT\n\n")
        
        # Generate and print QR code
        qr_img = generate_upi_qr_code(total_amount, bill_no)
        qr_data = image_to_escpos_bytes(qr_img)
        
    
        chunk_size = 512
        for i in range(0, len(qr_data), chunk_size):
            sock.send(qr_data[i:i + chunk_size])
        
       
        sock.send(f"UPI: {UPI_ID}\n".encode('utf-8'))
        sock.send(b"Amount already set\n")
        sock.send(b"----------------------------\n")
        
        # Footer
        sock.send(b"Thank You!\n")
        sock.send(b"Visit Again\n")
        sock.send(b"Exchange within 7 days\n")
        sock.send(b"GST: 27ABCDE1234F1Z5\n")
        
        # Paper feed and cut
        sock.send(b'\n\n\n\n')
        sock.send(b'\x1D\x56\x01') 
        
        print(" Receipt with QR code printed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"QR code print failed: {traceback.format_exc()}")
        raise RuntimeError(f"QR code print failed: {str(e)}")
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass

def find_bold_font():
    """Find bold fonts for better visibility"""
    candidates = [
        "C:\\Windows\\Fonts\\Arialbd.ttf",
        #"C:\\Windows\\Fonts\\arialbd.ttf",
        #"C:\\Windows\\Fonts\\Arial.ttf",
        #"C:\\Windows\\Fonts\\arial.ttf",
        #"C:\\Windows\\Fonts\\calibrib.ttf",
        #"C:\\Windows\\Fonts\\timesbd.ttf",
        #"/System/Library/Fonts/Arial.ttf",
        #"/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    return None

def render_receipt_image_3inch(bill_no: str, customer_name: str, mobile: str, 
                              email: str, items: List[Tuple[str, int, float, float]], 
                              subtotal: float, tax: float, total_amount: float) -> PILImage.Image:
    try:
        # Input validation
        if not bill_no or not customer_name or not mobile:
            raise ValueError("Missing required fields")
        
        if not items or len(items) == 0:
            raise ValueError("No items to print")
        
        # Validate amounts
        if subtotal < 0 or tax < 0 or total_amount < 0:
            raise ValueError("Amounts cannot be negative")
        width = 576
        dynamic_height = 4000  
        img = PILImage.new("L", (width, dynamic_height), 255)
        draw = ImageDraw.Draw(img)

        # Load optimized fonts
        font_path = find_bold_font()
        try:
            if font_path:
                title_font = ImageFont.truetype(font_path, 28)
                header_font = ImageFont.truetype(font_path, 24)
                normal_font = ImageFont.truetype(font_path, 20)
                small_font = ImageFont.truetype(font_path, 18)
            else:
                # Fallback to default font
                title_font = ImageFont.load_default()
                header_font = ImageFont.load_default()
                normal_font = ImageFont.load_default()
                small_font = ImageFont.load_default()
        except Exception as e:
            logger.warning(f"Font loading failed: {str(e)}")
            title_font = ImageFont.load_default()
            header_font = ImageFont.load_default()
            normal_font = ImageFont.load_default()
            small_font = ImageFont.load_default()

        x = 10  # Left margin
        y = 10  # Start position

        # ==================== HEADER SECTION ====================
        shop_name = "ELEVEN-7"
        shop_name_bbox = draw.textbbox((0, 0), shop_name, font=title_font)
        shop_name_width = shop_name_bbox[2] - shop_name_bbox[0]
        draw.text(((width - shop_name_width) // 2, y), shop_name, font=title_font, fill=0)
        y += 38
        
        shop_subname = "THE MEN'S WEAR"
        shop_subname_bbox = draw.textbbox((0, 0), shop_subname, font=header_font)
        shop_subname_width = shop_subname_bbox[2] - shop_subname_bbox[0]
        draw.text(((width - shop_subname_width) // 2, y), shop_subname, font=header_font, fill=0)
        y += 28
        
        address = "Panhala-Kolhapur Road, Kerle"
        address_bbox = draw.textbbox((0, 0), address, font=small_font)
        address_width = address_bbox[2] - address_bbox[0]
        draw.text(((width - address_width) // 2, y), address, font=small_font, fill=0)
        y += 20
        
        contact = "Phone: 9923234918"
        contact_bbox = draw.textbbox((0, 0), contact, font=small_font)
        contact_width = contact_bbox[2] - contact_bbox[0]
        draw.text(((width - contact_width) // 2, y), contact, font=small_font, fill=0)
        y += 22
        
        # Thick separator line
        draw.line((x, y, width - x, y), fill=0, width=3)
        y += 12

        # ==================== BILL INFO SECTION ====================
        bill_text = f"BILL NO: {bill_no}"
        draw.text((x, y), bill_text, font=header_font, fill=0)
        
        current_date = datetime.now().strftime('%d-%m-%Y %H:%M')
        date_bbox = draw.textbbox((0, 0), current_date, font=normal_font)
        date_width = date_bbox[2] - date_bbox[0]
        draw.text((width - date_width - x, y), current_date, font=normal_font, fill=0)
        y += 26
        
        cust_name_display = customer_name.upper()[:30]
        draw.text((x, y), f"CUSTOMER: {cust_name_display}", font=normal_font, fill=0)
        y += 24
        
        draw.text((x, y), f"MOBILE: {mobile}", font=normal_font, fill=0)
        y += 20
        
        if email and email.strip():
            email_valid, email_msg = validate_email(email)
            if email_valid:
                max_email_len = 40
                if len(email) > max_email_len:
                    display_email = email[:max_email_len-2] + ".."
                else:
                    display_email = email
                draw.text((x, y), f"EMAIL: {display_email}", font=normal_font, fill=0 )
                y += 20
        
        draw.line((x, y, width - x, y), fill=0, width=3)
        y += 10

        # ==================== ITEMS SECTION ====================
        # Items header
        item_col_x = x
        qty_col_x = width - 180
        amount_col_x = width - 80
        
        # Draw headers
        draw.text((item_col_x, y), "ITEM", font=header_font, fill=0)
        draw.text((qty_col_x - 20, y), "QTY", font=header_font, fill=0)
        draw.text((amount_col_x - 30, y), "AMOUNT", font=header_font, fill=0)
        y += 26
        
        # Line under header
        draw.line((x, y, width - x, y), fill=0, width=3)
        y += 8

        # Items list
        for (name, qty, price, line_total) in items:
            max_name_len = 22
            if len(name) > max_name_len:
                display_name = name[:max_name_len-2] + ".."
            else:
                display_name = name
            
            # Draw item name (left aligned)
            draw.text((item_col_x, y), display_name, font=normal_font, fill=0)
            
            # Draw quantity (center aligned in QTY column)
            qty_str = str(qty)
            qty_bbox = draw.textbbox((0, 0), qty_str, font=normal_font)
            qty_width = qty_bbox[2] - qty_bbox[0]
            draw.text((qty_col_x - qty_width//2, y), qty_str, font=normal_font, fill=0)
            
            # Draw amount
            amount_str = f"₹{line_total:.1f}"
            amount_bbox = draw.textbbox((0, 0), amount_str, font=normal_font)
            amount_width = amount_bbox[2] - amount_bbox[0]
            draw.text((amount_col_x - amount_width//2, y), amount_str, font=normal_font, fill=0)
            
            y += 26

        # Separator before totals
        y += 7
        draw.line((x, y, width - x, y), fill=0, width=3)
        y += 10

        # ==================== TOTALS SECTION ====================
        # Subtotal
        subtotal_text = f"SUB TOTAL: ₹{subtotal:.1f}"
        subtotal_bbox = draw.textbbox((0, 0), subtotal_text, font=normal_font)
        subtotal_width = subtotal_bbox[2] - subtotal_bbox[0]
        draw.text((width - subtotal_width - x, y), subtotal_text, font=normal_font, fill=0)
        y += 22
        
        # Tax
        tax_text = f"TAX: ₹{tax:.1f}"
        tax_bbox = draw.textbbox((0, 0), tax_text, font=normal_font)
        tax_width = tax_bbox[2] - tax_bbox[0]
        draw.text((width - tax_width - x, y), tax_text, font=normal_font, fill=0)
        y += 22
        
        # Grand Total
        total_text = f"TOTAL: ₹{total_amount:.1f}"
        total_bbox = draw.textbbox((0, 0), total_text, font=header_font)
        total_width = total_bbox[2] - total_bbox[0]
        draw.text((width - total_width - x, y), total_text, font=header_font, fill=0)
        y += 26

        # Final separator
        draw.line((x, y, width - x, y), fill=0, width=3)
        y += 15

        # ==================== QR CODE SECTION ====================
        # QR Code Title
        qr_title = "SCAN TO PAY VIA UPI"
        qr_title_bbox = draw.textbbox((0, 0), qr_title, font=header_font)
        qr_title_width = qr_title_bbox[2] - qr_title_bbox[0]
        draw.text(((width - qr_title_width) // 2, y), qr_title, font=header_font, fill=0)
        y += 30
        
        # Generate and add QR code
        try:
            qr_img = generate_upi_qr_code(total_amount, bill_no)
            qr_size = 250
            qr_img = qr_img.resize((qr_size, qr_size), PILImage.LANCZOS)
            
            qr_x = (width - qr_size) // 2
            img.paste(qr_img, (qr_x, y))
            y += qr_size + 14
            
            # UPI ID below QR code
            upi_text = f"UPI ID: {UPI_ID}"
            upi_bbox = draw.textbbox((0, 0), upi_text, font=small_font)
            upi_width = upi_bbox[2] - upi_bbox[0]
            draw.text(((width - upi_width) // 2, y), upi_text, font=small_font, fill=0)
            y += 18
            
            # Amount info
            amount_info = f"Amount: ₹{total_amount:.1f}"
            amount_bbox = draw.textbbox((0, 0), amount_info, font=small_font)
            amount_width = amount_bbox[2] - amount_bbox[0]
            draw.text(((width - amount_width) // 2, y), amount_info, font=small_font, fill=0)
            y += 20
            
        except Exception as qr_error:
            logger.warning(f"QR code generation failed: {str(qr_error)}")
            error_text = "QR Code Not Available"
            error_bbox = draw.textbbox((0, 0), error_text, font=normal_font)
            error_width = error_bbox[2] - error_bbox[0]
            draw.text(((width - error_width) // 2, y), error_text, font=normal_font, fill=0)
            y += 40

        # Separator after QR section
        draw.line((x, y, width - x, y), fill=0, width=3)
        y += 12

        # ==================== FOOTER SECTION ====================
        thank_text = "THANK YOU FOR SHOPPING!"
        thank_bbox = draw.textbbox((0, 0), thank_text, font=header_font)
        thank_width = thank_bbox[2] - thank_bbox[0]
        draw.text(((width - thank_width) // 2, y), thank_text, font=header_font, fill=0)
        y += 26
        
        visit_text = "PLEASE VISIT AGAIN"
        visit_bbox = draw.textbbox((0, 0), visit_text, font=normal_font)
        visit_width = visit_bbox[2] - visit_bbox[0]
        draw.text(((width - visit_width) // 2, y), visit_text, font=normal_font, fill=0)
        y += 22
        
        return_policy = "Exchange within 7 days with original bill"
        return_bbox = draw.textbbox((0, 0), return_policy, font=small_font)
        return_width = return_bbox[2] - return_bbox[0]
        draw.text(((width - return_width) // 2, y), return_policy, font=small_font, fill=0)
        y += 20
        
        gst_info = "GST No: 27ABCDE1234F1Z5"
        gst_bbox = draw.textbbox((0, 0), gst_info, font=small_font)
        gst_width = gst_bbox[2] - gst_bbox[0]
        draw.text(((width - gst_width) // 2, y), gst_info, font=small_font, fill=0)
        y += 18

        # Final paper feed space
        y += 10

        # Crop to actual content
        final_height = y
        if final_height > dynamic_height:
            final_height = dynamic_height
        img = img.crop((0, 0, width, final_height))
        return img
    except Exception as e:
        logger.error(f"Receipt image rendering failed: {traceback.format_exc()}")
        raise RuntimeError(f"Failed to generate receipt image: {str(e)}")

# ----------------- Professional PDF Generator -----------------

def generate_receipt_pdf(filename: str, bill_no: str, customer_name: str, mobile: str, 
                        email: str, items: List[Tuple[str, int, float, float]], 
                        subtotal: float, tax: float, total_amount: float):
    """Generate PDF receipt with validation and error handling"""
    try:
        # Input validation
        if not filename or not filename.endswith('.pdf'):
            raise ValueError("Invalid filename. Must be a PDF file")
        
        if not bill_no or not customer_name or not mobile:
            raise ValueError("Missing required fields for PDF")
        
        if not items or len(items) == 0:
            raise ValueError("No items for PDF")
        
        # Validate amounts
        if subtotal < 0 or tax < 0 or total_amount < 0:
            raise ValueError("Amounts cannot be negative")
        
        # Validate email if provided
        if email and email.strip():
            email_valid, email_msg = validate_email(email)
            if not email_valid:
                email = ""  # Don't include invalid email
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        
        doc = SimpleDocTemplate(filename, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=24, bottomMargin=18)
        styles = getSampleStyleSheet()
        story = []

        # Title Data
        story.append(Paragraph("<b>ELEVEN-7 | THE MEN'S WEAR</b>", styles["Title"]))
        story.append(Paragraph("Address: Panhala-Kolhapur Road, Kerle", styles["Normal"]))
        story.append(Paragraph("Phone: +919923234918  | Email: eleven7store@gmail.com", styles["Normal"]))
        story.append(Paragraph("<b>GST No:</b> 27ABCDE1234F1Z5", styles["Normal"]))
        story.append(Spacer(1, 8))

        # Bill Info
        story.append(Paragraph(f"<b>Bill No:</b> {bill_no}", styles["Normal"]))
        story.append(Paragraph(f"<b>Customer:</b> {customer_name}", styles["Normal"]))
        story.append(Paragraph(f"<b>Phone:</b> {mobile}", styles["Normal"]))

        if email and email.strip():
            story.append(Paragraph(f"<b>Email:</b> {email}", styles["Normal"]))

        story.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%d-%m-%Y %I:%M:%S %p')}", styles["Normal"]))
        story.append(Spacer(1, 8))

        # Items table
        data = [["Item Name", "Qty", "Rate (₹)", "Total (₹)"]]
        for name, qty, price, total in items:
            data.append([name, str(qty), f"{price:.2f}", f"{total:.2f}"])

        data.append(["", "", "Sub Total", f"{subtotal:.2f}"])
        data.append(["", "", "Tax", f"{tax:.2f}"])
        data.append(["", "", "Grand Total", f"{total_amount:.2f}"])

        col_widths = [85 * mm, 25 * mm, 35 * mm, 35 * mm]
        table = Table(data, colWidths=col_widths, hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#222")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (1,1), (-1,-1), "CENTER"),
            ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0,0), (-1,0), 8)
        ]))
        story.append(table)
        story.append(Spacer(1, 12))

        # ---------------- QR WITHOUT TEMP FILE -----------------
        try:
            qr_img = generate_upi_qr_code(total_amount, bill_no)

            # Save QR into memory instead of file
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")
            buf.seek(0)

            qr_pdf = Image(ImageReader(buf), width=60*mm, height=60*mm)
            qr_pdf.hAlign = "CENTER"
            story.append(qr_pdf)

            story.append(Paragraph("<b>Scan to Pay via UPI</b>", styles["Normal"]))
            story.append(Paragraph(f"<b>UPI ID:</b> {UPI_ID}", styles["Normal"]))
            story.append(Spacer(1, 12))

        except Exception as e:
            logger.warning(f"QR code in PDF failed: {str(e)}")
            story.append(Paragraph("<i>#QR Code generation failed</i>", styles["Normal"]))

        story.append(Paragraph("<b>Thank you for shopping!</b>", styles["Normal"]))
        story.append(Paragraph("Exchange within 7 days with original bill only.", styles["Normal"]))
        story.append(Spacer(1, 20))

        sig_style = ParagraphStyle(name="sig", alignment=2, fontSize=10)
        story.append(Paragraph("_", sig_style))
        story.append(Paragraph("Authorized Signature", sig_style))

        doc.build(story)
        logger.info(f"PDF generated successfully: {filename}")
        
    except PermissionError:
        raise RuntimeError(f"Permission denied to save PDF at: {filename}")
    except IOError as e:
        raise RuntimeError(f"File I/O error while saving PDF: {str(e)}")
    except Exception as e:
        logger.error(f"PDF generation failed: {traceback.format_exc()}")
        raise RuntimeError(f"Failed to generate PDF: {str(e)}")

# ----------------- Kivy UI Components -----------------

class Card(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        with self.canvas.before:
            Color(1, 1, 1, 1)
            self.rect = RoundedRectangle(pos=self.pos, size=self.size, radius=[20])
        self.bind(pos=self.update_rect, size=self.update_rect)

    def update_rect(self, *args):
        self.rect.pos = self.pos
        self.rect.size = self.size

class LoginScreen(Screen):
    show_password = BooleanProperty(False)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "login"
        self.auto_login_attempted = False  # Track if auto-login has been attempted
        layout = AnchorLayout(anchor_x="center", anchor_y="center", padding=40)
        self.card = Card(
            orientation="vertical", size_hint=(None, None), size=(400, 520), padding=35, spacing=25
        )
        title = Label(
            text="[b][color=#0A1172]11/7 Cloth Billing System Login[/color][/b]",
            markup=True,
            font_size=26,
            size_hint=(1, 0.14),
        )
        self.card.add_widget(title)

        form = GridLayout(cols=1, spacing=20, size_hint=(1, 0.42))
        self.username = TextInput(
            hint_text="Username", size_hint_y=None, height=55, multiline=False
        )
        self.password = TextInput(
            hint_text="Password", size_hint_y=None, height=55, multiline=False, password=True
        )

        pw_layout = BoxLayout(size_hint_y=None, height=55, spacing=8)
        toggle_btn = Button(
            text="Show",
            size_hint=(None, 1),
            width=70,
            background_color=(0.2, 0.6, 0.86, 1),
            color=(1, 1, 1, 1),
        )
        toggle_btn.bind(on_release=self.toggle_password)
        pw_layout.add_widget(self.password)
        pw_layout.add_widget(toggle_btn)

        form.add_widget(self.username)
        form.add_widget(pw_layout)
        
        # Remember me checkbox
        remember_layout = BoxLayout(size_hint_y=None, height=40, spacing=10)
        self.remember_check = CheckBox(size_hint=(None, None), size=(30, 30), active=False)
        remember_layout.add_widget(self.remember_check)
        remember_layout.add_widget(Label(text="Remember me", font_size=18, color=(0.2, 0.2, 0.2, 1)))
        form.add_widget(remember_layout)
        
        self.card.add_widget(form)

        login_btn = Button(
            text="Login",
            size_hint=(1, None),
            height=60,
            background_color=(0.1, 0.5, 0.8, 1),
            font_size=22,
        )
        login_btn.bind(on_release=self.login)
        self.card.add_widget(login_btn)

        btn_layout = GridLayout(cols=2, spacing=15, size_hint=(1, 0.17))
        forgot_btn = Button(
            text="Forgot Password?",
            background_color=(0, 0, 0, 0),
            color=(0.1, 0.5, 0.86, 1),
            font_size=18,
        )
        forgot_btn.bind(on_release=lambda instance: self.switch_screen("forgot"))

        change_btn = Button(
            text="Change Password",
            background_color=(0, 0, 0, 0),
            color=(0.1, 0.5, 0.86, 1),
            font_size=18,
        )
        change_btn.bind(on_release=lambda instance: self.switch_screen("change"))

        btn_layout.add_widget(forgot_btn)
        btn_layout.add_widget(change_btn)
        self.card.add_widget(btn_layout)

        layout.add_widget(self.card)
        self.add_widget(layout)

    def on_enter(self):
        """Called when the screen is displayed - try auto-login"""
        if not self.auto_login_attempted:
            Clock.schedule_once(lambda dt: self.attempt_auto_login(), 0.5)
            self.auto_login_attempted = True

    def attempt_auto_login(self):
        """Attempt to auto-login with saved credentials"""
        try:
            username, password = credentials_manager.load_credentials()
            if username and password:
                print(f"Attempting auto-login for user: {username}")
                success = self.auto_login(username, password)
                if not success:
                    # Auto-login failed, populate fields
                    self.username.text = username
                    self.password.text = password
                    self.remember_check.active = True
                    print("Auto-login failed, credentials populated for manual login")
                else:
                    print("Auto-login successful!")
        except Exception as e:
            logger.error(f"Auto-login attempt failed: {str(e)}")
            print(f"Auto-login error: {str(e)}")

    def toggle_password(self, instance):
        try:
            self.show_password = not self.show_password
            self.password.password = not self.show_password
            instance.text = "Hide" if self.show_password else "Show"
        except Exception as e:
            logger.error(f"Toggle password failed: {str(e)}")
            self.show_popup("Error", "Failed to toggle password visibility")

    def login(self, instance):
        username = self.username.text.strip()
        password = self.password.text.strip()
        
        # Validation
        if not username or not password:
            self.show_popup("Error", "Username and password are required.")
            return
        
        if len(username) < 3 or len(username) > 50:
            self.show_popup("Error", "Username must be 3-50 characters.")
            return
        
        if len(password) < 4:
            self.show_popup("Error", "Password must be at least 4 characters.")
            return
        
        try:
            data = {"username": username, "password": password}
            
            response = requests.post(
                f"{API_BASE}/login/", 
                json=data,
                timeout=15,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                token = data.get("token")
                if token:
                    self.manager.token = token
                    
                    # Check if remember me is checked
                    if self.remember_check.active:
                        # Save credentials
                        if credentials_manager.save_credentials(username, password):
                            print("Credentials saved successfully")
                        else:
                            print("Failed to save credentials")
                    else:
                        # Delete any existing saved credentials
                        credentials_manager.delete_credentials()
                    
                    # Clear fields and navigate to billing
                    self.username.text = ""
                    self.password.text = ""
                    self.show_popup("Success", "Login successful! 🎉")
                    self.manager.transition.direction = "left"
                    self.manager.current = "billing"
                else:
                    self.show_popup("Error", "No authentication token received")
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', 'Invalid credentials')
                except:
                    error_msg = f"Server error: {response.status_code}"
                self.show_popup("Error", error_msg)
                
        except requests.exceptions.ConnectionError:
            self.show_popup("Error", "Cannot connect to server. Make sure Django is running on 127.0.0.1:8000")
        except requests.exceptions.Timeout:
            self.show_popup("Error", "Connection timeout. Server is not responding.")
        except requests.exceptions.RequestException as e:
            self.show_popup("Error", f"Network error: {str(e)}")
        except Exception as e:
            logger.error(f"Login failed: {traceback.format_exc()}")
            self.show_popup("Error", f"Login failed: {str(e)}")

    def auto_login(self, username, password):
        """Auto login with saved credentials"""
        try:
            data = {"username": username, "password": password}
        
            response = requests.post(
                f"{API_BASE}/login/", 
                json=data,
                timeout=15,
                headers={'Content-Type': 'application/json'}
            )
        
            if response.status_code == 200:
                data = response.json()
                token = data.get("token")
                if token:
                    self.manager.token = token
                    # Transition to billing screen
                    self.manager.transition.direction = "left"
                    self.manager.current = "billing"
                    return True
            # If we get here, auto login failed
            return False
        except Exception as e:
            logger.error(f"Auto login failed: {traceback.format_exc()}")
            return False

    def switch_screen(self, screen_name, direction="left"):
        try:
            self.manager.transition.direction = direction
            self.manager.current = screen_name
        except Exception as e:
            logger.error(f"Screen switch failed: {str(e)}")
            self.show_popup("Error", "Navigation error occurred")

    def show_popup(self, title, message):
        try:
            Popup(title=title, content=Label(text=message), size_hint=(0.6, 0.4)).open()
        except Exception as e:
            logger.error(f"Popup failed: {str(e)}")

class ForgotPasswordScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "forgot"
        layout = AnchorLayout(anchor_x="center", anchor_y="center", padding=40)
        self.card = Card(
            orientation="vertical", size_hint=(None, None), size=(400, 320), padding=35, spacing=25
        )
        title = Label(
            text="[b][color=#0A1172]Forgot Password?[/color][/b]",
            markup=True,
            font_size=26,
            size_hint=(1, 0.2),
        )
        self.card.add_widget(title)

        self.username = TextInput(
            hint_text="Username", size_hint_y=None, height=55, multiline=False
        )
        self.card.add_widget(self.username)

        reset_btn = Button(
            text="Reset Password",
            size_hint=(1, None),
            height=60,
            background_color=(0.1, 0.5, 0.8, 1),
        )
        reset_btn.bind(on_release=self.reset_password)
        self.card.add_widget(reset_btn)

        back_btn = Button(
            text="Back to Login",
            size_hint=(1, None),
            height=40,
            background_color=(0.8, 0.8, 0.8, 1),
            color=(0, 0, 0, 1),
        )
        back_btn.bind(on_release=lambda instance: self.switch_screen("login", "right"))
        self.card.add_widget(back_btn)

        layout.add_widget(self.card)
        self.add_widget(layout)

    def reset_password(self, instance):
        username = self.username.text.strip()
        if not username:
            self.show_popup("Error", "Enter username.")
            return
        
        if len(username) < 3 or len(username) > 50:
            self.show_popup("Error", "Username must be 3-50 characters.")
            return
        
        try:
            response = requests.post(
                f"{API_BASE}/forgot-password/", 
                json={"username": username},
                timeout=15
            )
            
            if response.status_code == 200:
                msg = response.json().get("message") or "Password reset successful!"
                self.show_popup("Success", msg)
            else:
                try:
                    error_data = response.json()
                    msg = error_data.get("error") or error_data.get("message") or "Something went wrong"
                except:
                    msg = f"Server error: {response.status_code}"
                self.show_popup("Error", msg)
        except requests.exceptions.ConnectionError:
            self.show_popup("Error", "Cannot connect to server.")
        except requests.exceptions.Timeout:
            self.show_popup("Error", "Request timeout.")
        except Exception as e:
            logger.error(f"Password reset failed: {traceback.format_exc()}")
            self.show_popup("Error", f"Cannot process request: {str(e)}")

    def switch_screen(self, screen_name, direction="right"):
        try:
            self.manager.transition.direction = direction
            self.manager.current = screen_name
        except Exception as e:
            logger.error(f"Screen switch failed: {str(e)}")
            self.show_popup("Error", "Navigation error")

    def show_popup(self, title, message):
        try:
            Popup(title=title, content=Label(text=message), size_hint=(0.6, 0.4)).open()
        except Exception as e:
            logger.error(f"Popup failed: {str(e)}")

class ChangePasswordScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "change"
        layout = AnchorLayout(anchor_x="center", anchor_y="center", padding=40)
        self.card = Card(
            orientation="vertical", size_hint=(None, None), size=(400, 380), padding=35, spacing=25
        )
        title = Label(
            text="[b][color=#0A1172]Change Password[/color][/b]",
            markup=True,
            font_size=26,
            size_hint=(1, 0.2),
        )
        self.card.add_widget(title)

        self.old_password = TextInput(
            hint_text="Old Password", size_hint_y=None, height=55, multiline=False, password=True
        )
        self.card.add_widget(self.old_password)

        self.new_password = TextInput(
            hint_text="New Password", size_hint_y=None, height=55, multiline=False, password=True
        )
        self.card.add_widget(self.new_password)

        change_btn = Button(
            text="Change Password",
            size_hint=(1, None),
            height=60,
            background_color=(0.1, 0.5, 0.8, 1),
        )
        change_btn.bind(on_release=self.change_password)
        self.card.add_widget(change_btn)

        back_btn = Button(
            text="Back to Login",
            size_hint=(1, None),
            height=40,
            background_color=(0.8, 0.8, 0.8, 1),
            color=(0, 0, 0, 1),
        )
        back_btn.bind(on_release=lambda instance: self.switch_screen("login", "right"))
        self.card.add_widget(back_btn)

        layout.add_widget(self.card)
        self.add_widget(layout)

    def change_password(self, instance):
        old_pass = self.old_password.text.strip()
        new_pass = self.new_password.text.strip()
        
        # Validation
        if not old_pass or not new_pass:
            self.show_popup("Error", "Fill all fields.")
            return
        
        if len(old_pass) < 4 or len(new_pass) < 4:
            self.show_popup("Error", "Password must be at least 4 characters.")
            return
        
        if old_pass == new_pass:
            self.show_popup("Error", "New password must be different from old password.")
            return
        
        if not hasattr(self.manager, "token") or self.manager.token is None:
            self.show_popup("Error", "You must login first.")
            return
        
        headers = {"Authorization": f"Token {self.manager.token}"}
        try:
            response = requests.put(
                f"{API_BASE}/change-password/",
                json={"old_password": old_pass, "new_password": new_pass},
                headers=headers,
                timeout=15
            )
            
            if response.status_code == 200:
                msg = response.json().get("message") or "Password changed successfully!"
                self.show_popup("Success", msg)
                self.old_password.text = ""
                self.new_password.text = ""
                
                # Delete saved credentials since password changed
                credentials_manager.delete_credentials()
            else:
                try:
                    error_data = response.json()
                    msg = error_data.get("error") or error_data.get("message") or "Change password failed"
                except:
                    msg = f"Server error: {response.status_code}"
                self.show_popup("Error", msg)
        except requests.exceptions.ConnectionError:
            self.show_popup("Error", "Cannot connect to server.")
        except requests.exceptions.Timeout:
            self.show_popup("Error", "Request timeout.")
        except Exception as e:
            logger.error(f"Password change failed: {traceback.format_exc()}")
            self.show_popup("Error", f"Cannot process request: {str(e)}")

    def switch_screen(self, screen_name, direction="right"):
        try:
            self.manager.transition.direction = direction
            self.manager.current = screen_name
        except Exception as e:
            logger.error(f"Screen switch failed: {str(e)}")
            self.show_popup("Error", "Navigation error")

    def show_popup(self, title, message):
        try:
            Popup(title=title, content=Label(text=message), size_hint=(0.6, 0.4)).open()
        except Exception as e:
            logger.error(f"Popup failed: {str(e)}")

class BillingScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "billing"
        
        # Main layout
        self.layout = BoxLayout(orientation="vertical", spacing=10, padding=20)

        # ================ TOP HEADER BAR ================
        header_bar = BoxLayout(size_hint_y=None, height=50, spacing=10)
        
        # Left: Search Bills button
        search_btn = Button(
            text="Search Bills",
            size_hint=(None, 1),
            width=180,
            background_color=(0.2, 0.6, 0.8, 1),
            color=(1, 1, 1, 1),
            font_size=22,
            bold = True
        )
        search_btn.bind(on_release=self.open_search)
        header_bar.add_widget(search_btn)
        
        # Center: Title
        header_bar.add_widget(Label())  # Spacer
        
        title_label = Label(
            text="[b][color=#0A1172]ELEVEN-7 BILLING SYSTEM[/color][/b]",
            markup=True,
            font_size=32,
            size_hint=(1, 1),
            halign="center",
            bold = True
        )
        header_bar.add_widget(title_label)
        
        header_bar.add_widget(Label())  # Spacer
        
        # Right: Settings and Products buttons
        right_buttons = BoxLayout(size_hint=(None, 1), width=220, spacing=10)
        
        settings_btn = Button(
            text="Settings",
            size_hint=(1, 1),
            background_color=(0.1, 0.5, 0.7, 1),
            color=(1, 1, 1, 1),
            font_size=22,
            bold = True
        )
        settings_btn.bind(on_release=self.open_settings)
        
        product_btn = Button(
            text="Products",
            size_hint=(1, 1),
            background_color=(0.2, 0.7, 0.3, 1),
            color=(1, 1, 1, 1),
            font_size=22,
            bold = True
        )
        product_btn.bind(on_release=self.open_products)
        
        right_buttons.add_widget(settings_btn)
        right_buttons.add_widget(product_btn)
        header_bar.add_widget(right_buttons)
        
        self.layout.add_widget(header_bar)

        # ================ MAIN CONTENT AREA ================
        content_area = BoxLayout(orientation="horizontal", spacing=15, size_hint=(1, 0.8))
        
        # ================ LEFT PANEL (Form Fields) ================
        left_panel = BoxLayout(orientation="vertical", size_hint_x=0.65, spacing=15)
        
        # Customer Information Card
        cust_card = BoxLayout(
            orientation="vertical", 
            size_hint_y=None, 
            height=350,
            padding=15,
            spacing=5
        )
        
        # Card background
        with cust_card.canvas.before:
            Color(0.95, 0.95, 0.95, 1)
            cust_card.rect = RoundedRectangle(pos=cust_card.pos, size=cust_card.size, radius=[15])
        
        cust_card.bind(pos=lambda obj, pos: setattr(cust_card.rect, 'pos', pos),
                      size=lambda obj, size: setattr(cust_card.rect, 'size', size))
        
        cust_card.add_widget(Label(
            text="[b][color=#0A1172]CUSTOMER INFORMATION[/color][/b]", 
            markup=True,
            font_size=26,
            size_hint_y=None,
            height=50,
            bold=True,
            
        ))
        
        cust_grid = GridLayout(cols=2, spacing=15, padding=(0, 10, 0, 0))
        
        # Mobile Number
        cust_grid.add_widget(Label(
            text="Mobile Number*", 
            font_size=24, 
            color=(0.2, 0.2, 0.2, 1), 
            size_hint_y=None, 
            height=60,
            halign="right",
            bold=True
        ))
        self.entry_mob = TextInput(
            multiline=False, 
            hint_text="10-digit mobile", 
            font_size=22, 
            size_hint_y=None, 
            height=60,
            background_color=(1, 1, 1, 1),
            foreground_color=(0, 0, 0, 1),
            padding=(10, 10)
        )
        cust_grid.add_widget(self.entry_mob)
        
        # Customer Name
        cust_grid.add_widget(Label(
            text="Customer Name*", 
            font_size=22, 
            color=(0.2, 0.2, 0.2, 1), 
            size_hint_y=None, 
            height=60,
            halign="right",
            bold=True
        ))
        self.entry_name = TextInput(
            multiline=False, 
            hint_text="Full name", 
            font_size=22, 
            size_hint_y=None, 
            height=60,
            background_color=(1, 1, 1, 1),
            foreground_color=(0, 0, 0, 1),
            padding=(10, 10)
        )
        cust_grid.add_widget(self.entry_name)
        
        # Customer Email
        cust_grid.add_widget(Label(
            text="Customer Email", 
            font_size=22, 
            color=(0.2, 0.2, 0.2, 1), 
            size_hint_y=None, 
            height=60,
            halign="right",
            bold=True
        ))
        self.entry_email = TextInput(
            multiline=False, 
            hint_text="Optional email", 
            font_size=22, 
            size_hint_y=None, 
            height=60,
            background_color=(1, 1, 1, 1),
            foreground_color=(0, 0, 0, 1),
            padding=(10, 10)
        )
        cust_grid.add_widget(self.entry_email)
        
        cust_card.add_widget(cust_grid)
        left_panel.add_widget(cust_card)
        
        # Product Information Card
        prod_card = BoxLayout(
            orientation="vertical", 
            size_hint_y=None, 
            height=400,
            padding=15,
            spacing=5,
            
        )
        
        # Card background
        with prod_card.canvas.before:
            Color(0.95, 0.95, 0.95, 1)
            prod_card.rect = RoundedRectangle(pos=prod_card.pos, size=prod_card.size, radius=[15])
        
        prod_card.bind(pos=lambda obj, pos: setattr(prod_card.rect, 'pos', pos),
                      size=lambda obj, size: setattr(prod_card.rect, 'size', size))
        
        prod_card.add_widget(Label(
            text="[b][color=#0A1172]PRODUCT INFORMATION[/color][/b]", 
            markup=True,
            font_size=26,
            size_hint_y=None,
            height=50
        ))
        
        prod_grid = GridLayout(cols=2, spacing=12, padding=(0, 10, 0, 0))
        
        # Category
        prod_grid.add_widget(Label(
            text="Category*", 
            font_size=22, 
            color=(0.2, 0.2, 0.2, 1), 
            size_hint_y=None, 
            height=60,
            halign="right",
            bold=True
        ))
        self.combo_category = Spinner(
            text="Select Category", 
            values=["Select Category"], 
            font_size=22,
            bold=True,
            size_hint_y=None, 
            height=60,
            #background_color=(1, 1, 1, 1),
            color=(1, 1, 1, 1)
        )
        prod_grid.add_widget(self.combo_category)
        
        # Subcategory
        prod_grid.add_widget(Label(
            text="Subcategory*", 
            font_size=22, 
            color=(0.2, 0.2, 0.2, 1), 
            size_hint_y=None, 
            height=60,
            halign="right",
            bold=True
        ))
        self.combo_subcategory = Spinner(
            text="Select Subcategory", 
            values=["Select Subcategory"], 
            font_size=22, 
            size_hint_y=None, 
            height=60,
            bold=True,
           # background_color=None,
            color=(1, 1, 1, 1)
        )
        prod_grid.add_widget(self.combo_subcategory)
        
        # Price
        prod_grid.add_widget(Label(
            text="Price (₹)*", 
            font_size=22, 
            color=(0.2, 0.2, 0.2, 1), 
            size_hint_y=None, 
            height=60,
            halign="right",
            bold=True
        ))
        self.price_input = TextInput(
            text="0.00", 
            multiline=False, 
            readonly=True, 
            font_size=18, 
            size_hint_y=None, 
            height=50,
            background_color=(0.9, 0.9, 0.9, 1),
            foreground_color=(0, 0, 0, 1),
            padding=(10, 10)
        )
        prod_grid.add_widget(self.price_input)
        
        # Quantity
        prod_grid.add_widget(Label(
            text="Quantity*", 
            font_size=22, 
            color=(0.2, 0.2, 0.2, 1), 
            size_hint_y=None, 
            height=60,
            halign="right",
            bold=True
        ))
        self.qty_input = TextInput(
            text="1", 
            multiline=False, 
            hint_text="Quantity", 
            font_size=22, 
            size_hint_y=None,
            height=60,
            background_color=(1, 1, 1, 1),
            foreground_color=(0, 0, 0, 1),
            padding=(10, 10)
        )
        prod_grid.add_widget(self.qty_input)
        
        prod_card.add_widget(prod_grid)
        
        left_panel.add_widget(prod_card)
        
        # Add expanding widget to push everything up
        left_panel.add_widget(Widget(size_hint_y=1))
        
        # ================ RIGHT PANEL (Bill Area - FIXED SIZE) ================
        right_panel = BoxLayout(orientation="vertical", size_hint_x=0.35, spacing=10, size_hint_y=None, height=790)
        
        # Add a colored background to the entire right panel
        with right_panel.canvas.before:
            # Light blue background for the entire right panel
            Color(0.95, 0.97, 1, 1)  # Very light blue
            right_panel.background = RoundedRectangle(
                pos=right_panel.pos, 
                size=right_panel.size, 
                radius=[15]
            )

        # Bind the background rectangle position and size
        right_panel.bind(
            pos=lambda obj, pos: setattr(right_panel.background, 'pos', pos),
            size=lambda obj, size: setattr(right_panel.background, 'size', size)
        )

        # Bill header with card styling - CHANGED TO MATCH NEW DESIGN
        bill_header_card = BoxLayout(
            orientation="vertical",
            size_hint_y=None,
            height=60,  # Slightly increased height
            padding=[15, 10],
            spacing=5,
        )

        # Change header to a nice gradient-like color
        with bill_header_card.canvas.before:
            # Gradient blue header
            Color(0.1, 0.4, 0.7, 1)  # Medium blue
            bill_header_card.rect = RoundedRectangle(
                pos=bill_header_card.pos, 
                size=bill_header_card.size, 
                radius=[10, 10, 0, 0]  # Rounded top corners only
            )

        bill_header_card.bind(
            pos=lambda obj, pos: setattr(bill_header_card.rect, 'pos', pos),
            size=lambda obj, size: setattr(bill_header_card.rect, 'size', size)
        )

        # Update bill title with better styling
        bill_title = Label(
            text="[b][color=FFFFFF]BILL PREVIEW[/color][/b]",  # White text
            markup=True,
            font_size=22,  # Slightly smaller
            halign="center",
            valign="middle",
            bold=True
        )
        bill_header_card.add_widget(bill_title)
        right_panel.add_widget(bill_header_card)
        
        # Bill area in ScrollView with FIXED size
        bill_scroll = ScrollView(
            size_hint=(1, 1),
            do_scroll_x=False,
            do_scroll_y=True,
            bar_width=12,
            bar_color=[0.2, 0.4, 0.6, 0.8],  # Blue scrollbar
            bar_inactive_color=[0.2, 0.4, 0.6, 0.3],
            scroll_type=['bars', 'content'],
            effect_cls='ScrollEffect',
            bar_pos_y='right'
        )
        
        # Create bill area container with enhanced card styling
        self.bill_container = BoxLayout(
            orientation='vertical', 
            size_hint_y=None,
            padding=[10, 10],  # Increased padding
            spacing=8
        )
        
        # Enhanced background for bill container
        with self.bill_container.canvas.before:
            # White background with shadow effect
            Color(1, 1, 1, 1)  # Pure white
            self.bill_container.rect = RoundedRectangle(
                pos=(self.bill_container.pos[0] + 2, self.bill_container.pos[1] - 2),  # Shadow offset
                size=self.bill_container.size, 
                radius=[0, 0, 10, 10]  # Rounded bottom corners only
            )
            # Main card
            Color(1, 1, 1, 1)
            self.bill_container.main_rect = RoundedRectangle(
                pos=self.bill_container.pos, 
                size=self.bill_container.size, 
                radius=[0, 0, 10, 10]
            )
            # Top border to match header
            Color(0.1, 0.4, 0.7, 1)
            self.bill_container.top_border = Rectangle(
                pos=self.bill_container.pos,
                size=(self.bill_container.size[0], 3)
            )

        # Update bindings for the new background elements
        def update_bill_background(instance, value):
            instance.rect.pos = (instance.pos[0] + 2, instance.pos[1] - 2)
            instance.rect.size = instance.size
            instance.main_rect.pos = instance.pos
            instance.main_rect.size = instance.size
            instance.top_border.pos = instance.pos
            instance.top_border.size = (instance.size[0], 3)

        self.bill_container.bind(pos=update_bill_background, size=update_bill_background)
        
        # Update the bill label with better styling
        self.bill_label = Label(
            text="",
            font_size=32,  # Slightly smaller for better readability
            size_hint_y=None,
            markup=True,
            halign="left",  # Left align for better readability
            valign="top",
            color=(0.1, 0.1, 0.1, 1),  # Dark gray text
            text_size=(None, None),  # Auto text size
            padding=(5, 5)
        )
        self.bill_label.bind(texture_size=self.update_bill_label_size)
        
        self.bill_container.add_widget(self.bill_label)
        bill_scroll.add_widget(self.bill_container)
        right_panel.add_widget(bill_scroll)
        
        # Add a subtle footer to the bill preview
        footer_layout = BoxLayout(
            size_hint_y=None,
            height=30,
            padding=[10, 0]
        )

        footer_label = Label(
            text="[color=666666][size=24]ELEVEN-7 Billing System[/size][/color]",
            markup=True,
            halign="center"
        )
        footer_layout.add_widget(footer_label)
        right_panel.add_widget(footer_layout)
        
        # Add both panels to content area
        content_area.add_widget(left_panel)
        content_area.add_widget(right_panel)
        
        self.layout.add_widget(content_area)
        
        # ================ BOTTOM HORIZONTAL BUTTON LAYOUT ================
        bottom_button_layout = BoxLayout(
            size_hint_y=None,
            height=80,
            spacing=20,
            padding=(20, 10, 20, 10)
        )
        
        # ADD TO CART button
        add_to_cart_btn = Button(
            text="ADD TO CART",
            background_color=(0.2, 0.7, 0.3, 1),
            font_size=22,
            color=(1, 1, 1, 1),
            bold = True
        
        )
        add_to_cart_btn.bind(on_press=self.add_item)
        
        # PRINT BILL button
        print_bill_btn = Button(
            text=" PRINT BILL",
            background_color=(0.2, 0.5, 0.8, 1),
            font_size=22,
            color=(1, 1, 1, 1),
            bold = True
        )
        print_bill_btn.bind(on_press=self.print_and_save_bill)
        
        # CLEAR ALL button
        clear_all_btn = Button(
            text="CLEAR ALL",
            background_color=(0.86, 0.2, 0.27, 1),
            font_size=22,
            color=(1, 1, 1, 1),
            bold = True
        )
        clear_all_btn.bind(on_press=self.clear_data)
        
        # Add buttons to the layout
        bottom_button_layout.add_widget(add_to_cart_btn)
        bottom_button_layout.add_widget(print_bill_btn)
        bottom_button_layout.add_widget(clear_all_btn)
        
        # Add the bottom button layout to the main layout
        self.layout.add_widget(bottom_button_layout)
        
        self.add_widget(self.layout)

        # Data containers
        self.categories = []
        self.subcategories_map = {}
        self.cart_items = []
        self.line_totals = []
        self.bill_no = str(random.randint(1000, 9999))

        # Bind spinner selection events
        self.combo_category.bind(text=self.load_subcategories)
        self.combo_subcategory.bind(text=self.update_price)

        Clock.schedule_once(lambda dt: self.load_categories())
        self.refresh_bill_area_header()

    def update_bill_label_size(self, instance, value):
        """Update bill label height based on content"""
        if instance.texture_size:
            instance.height = max(400, instance.texture_size[1])
            self.bill_container.height = max(500, instance.texture_size[1] + 20)

    def refresh_bill_area_header(self):
        """Refresh the bill area with header information"""
        try:
            bill_text = (
                f"[color=222222][size=30][b]                  ELEVEN-7 CLOTH SHOP[/b][/size][/color]\n"
                f"[size=22][color=444444]                               Panhala-Kolhapur Road, Kerle[/color][/size]\n"
                f"[size=22][color=666666]                                      Phone: 9923234918[/color][/size]\n"
                f"{'=' * 30}[/color]\n"  # Blue separator
                #f"[color=1E90FF]{'-' * 20}[/color]\n\n"  # Blue separator
                f"[size=22]Bill No: {self.bill_no}[/color][/size]                       "
                f"[size=22][color=444444]Date: {datetime.now().strftime('%d-%m-%Y / %H:%M')}[/color][/size]\n"
                f"{'=' * 30}[/color]\n"  # Blue separator
                f"[size=22]Customer : [b][color=0A1172]{self.entry_name.text if self.entry_name.text else '__________'}[/color][/b][/size]\n"
                f"[size=22]Mobile      : [b][color=0A1172]{self.entry_mob.text if self.entry_mob.text else '__________'}[/color][/b][/size]\n"
            )
            
            if self.entry_email.text.strip():
                bill_text += f"[size=22][color=444444]Email: {self.entry_email.text}[/color][/size]\n"
                
            bill_text += (
                f"{'=' * 30}[/color]\n"
                f"[size=22]{'Item':<25}                      {'Qty':>5}                          {'Amount':>10}[/color][/size]\n"
                f"{'=' * 30}[/color]\n"
            )
            self.bill_label.text = bill_text
        except Exception as e:
            logger.error(f"Refresh bill header failed: {str(e)}")

    def add_item(self, instance):
        """Add item to cart with validation"""
        try:
            if not self.validate_customer_info():
                return
            
            if not self.validate_product_selection():
                return
            
            qty = int(float(self.qty_input.text))
            price = float(self.price_input.text)
            line_total = round(price * qty, 2)
            item_name = self.combo_subcategory.text
            
            # Check if item already exists in cart
            for i, (name, existing_qty, existing_price, existing_total) in enumerate(self.cart_items):
                if name == item_name and existing_price == price:
                    new_qty = existing_qty + qty
                    new_total = round(new_qty * price, 2)
                    self.cart_items[i] = (item_name, new_qty, price, new_total)
                    self.line_totals[i] = new_total
                    
                    # Update bill display
                    self.refresh_bill_area_header()
                    bill_text = self.bill_label.text
                    for name, qty, price, total in self.cart_items:
                        display_name = name[:22] if len(name) <= 22 else name[:19] + "..."
                        # Use black text for items to ensure visibility
                        bill_text += f"[color=000000][size=14]{display_name:<25} {qty:>5} ₹{total:>9.2f}[/size][/color]\n"
                    
                    self.bill_label.text = bill_text
                    
                    # Update totals
                    self.update_totals()
                    self.qty_input.text = "1"
                    self.update_bill_label_size(self.bill_label, self.bill_label.texture_size)
                    return
            
            # Add new item
            self.cart_items.append((item_name, qty, round(price, 2), line_total))
            self.line_totals.append(line_total)
            
            # Update bill display
            display_name = item_name[:22] if len(item_name) <= 22 else item_name[:19] + "..."
            # Use black text for items to ensure visibility
            self.bill_label.text += f"[color=000000][size=14]{display_name:<25} {qty:>5} ₹{line_total:>9.2f}[/size][/color]\n"
            self.qty_input.text = "1"
            
            # Update totals
            self.update_totals()
            self.update_bill_label_size(self.bill_label, self.bill_label.texture_size)
            
        except ValueError as e:
            logger.error(f"Invalid value in add_item: {str(e)}")
            self.show_popup("Error", "Invalid numerical value. Please check quantity and price.")
        except Exception as e:
            logger.error(f"Add item failed: {traceback.format_exc()}")
            self.show_popup("Error", f"Failed to add item: {str(e)}")

    def update_totals(self):
        """Update totals section in bill area"""
        try:
            if not self.cart_items:
                return
            
            # Calculate totals
            subtotal = sum(self.line_totals)
            tax_amount = 0.0
            total_amount = subtotal + tax_amount
            
            # Clear and rebuild bill display
            self.refresh_bill_area_header()
            bill_text = self.bill_label.text
            for name, qty, price, total in self.cart_items:
                display_name = name[:22] if len(name) <= 22 else name[:19] + "..."
                # Use black text for items to ensure visibility
                bill_text += f"[color=000000][size=20]{display_name:<25}                        {qty:>10}                            ₹{total:>9.2f}[/size][/color]\n"
            
            # Add totals section with better styling
            bill_text += f"{'=' * 30}[/color]\n"
            bill_text += f"[size=22][color=444444]Subtotal:{' ' * 20}[b]₹{subtotal:>10.2f}[/b][/color][/size]\n"
            bill_text += f"[size=22][color=444444]Tax:{' ' * 24}[b]₹{tax_amount:>10.2f}[/b][/color][/size]\n"
            bill_text += f"{'=' * 30}[/color]\n"
            bill_text += f"[size=24][b][color=0A1172]TOTAL:{' ' * 20}₹{total_amount:>10.2f}[/color][/b][/size]\n"
            bill_text += f"{'=' * 30}[/color]\n\n"
            bill_text += f"[size=23][color=008000][b]Thank You! Visit Again[/b][/color][/size]\n"
            bill_text += f"[size=18][color=666666]GST: 27ABCDE1234F1Z5[/color][/size]\n"
            
            self.bill_label.text = bill_text
            self.update_bill_label_size(self.bill_label, self.bill_label.texture_size)
            
        except Exception as e:
            logger.error(f"Update totals failed: {str(e)}")

    def gen_bill(self, instance):
        """Generate final bill with validation"""
        try:
            if not self.validate_customer_info():
                return
            
            if not self.cart_items:
                self.show_popup("Error", "Please add items first!")
                return  
            # Already updated in add_item and update_totals
            self.show_popup("Success", "Bill generated successfully!")
            
        except Exception as e:
            logger.error(f"Generate bill failed: {traceback.format_exc()}")
            self.show_popup("Error", f"Failed to generate bill: {str(e)}")

    def open_search(self, instance):
        """Open search bills screen"""
        try:
            self.manager.transition.direction = "left"
            self.manager.current = "search_bills"
        except Exception as e:
            logger.error(f"Open search failed: {str(e)}")
            self.show_popup("Error", "Failed to open search screen")

    def open_products(self, instance):
        """Open product management screen"""
        try:
            self.manager.transition.direction = "left"
            self.manager.current = "products"
        except Exception as e:
            logger.error(f"Open products failed: {str(e)}")
            self.show_popup("Error", "Failed to open product management")

    def open_settings(self, instance):
        """Open settings popup"""
        try:
            content = BoxLayout(orientation="vertical", spacing=10, padding=10)
            logout_btn = Button(text="Logout", size_hint_y=None, height=50)
            change_pw_btn = Button(text="Change Password", size_hint_y=None, height=50)
            close_btn = Button(text="Close", size_hint_y=None, height=50)

            content.add_widget(logout_btn)
            content.add_widget(change_pw_btn)
            content.add_widget(close_btn)

            popup = Popup(title="Settings", content=content, size_hint=(0.5, 0.4))
            popup.open()

            logout_btn.bind(on_release=lambda x: self.logout(popup))
            change_pw_btn.bind(on_release=lambda x: self.open_change_password(popup))
            close_btn.bind(on_release=popup.dismiss)
        except Exception as e:
            logger.error(f"Open settings failed: {str(e)}")
            self.show_popup("Error", "Failed to open settings")

    def logout(self, popup=None):
        """Logout user"""
        try:
            if popup:
                popup.dismiss()
            # Delete saved credentials on logout
            credentials_manager.delete_credentials()
            self.manager.token = None
            self.manager.transition.direction = "right"
            self.manager.current = "login"
        except Exception as e:
            logger.error(f"Logout failed: {str(e)}")
            self.show_popup("Error", "Logout failed")

    def open_change_password(self, popup):
        """Open change password screen"""
        try:
            popup.dismiss()
            self.manager.transition.direction = "left"
            self.manager.current = "change"
        except Exception as e:
            logger.error(f"Open change password failed: {str(e)}")
            self.show_popup("Error", "Navigation failed")

    def load_categories(self, dt=None):
        """Load categories from API"""
        try:
            response = requests.get(f"{API_BASE}/categories/", timeout=10)
            if response.status_code == 200:
                self.categories = response.json()
                names = [c["name"] for c in self.categories]
                self.combo_category.values = ["Select Category"] + names
            else:
                raise Exception(f"API returned {response.status_code}")
        except requests.exceptions.ConnectionError:
            logger.warning("Using fallback categories due to connection error")
        except Exception as e:
            logger.error(f"Load categories failed: {traceback.format_exc()}")
            self.show_popup("Warning", "Could not load categories.")

    def load_subcategories(self, spinner, text):
        """Load subcategories based on selected category"""
        if text == "Select Category":
            self.combo_subcategory.values = ["Select Subcategory"]
            self.combo_subcategory.text = "Select Subcategory"
            self.price_input.text = "0"
            return
        
        try:
            cat = next((c for c in self.categories if c["name"] == text), None)
            if cat:
                cat_id = cat.get("id")
                response = requests.get(f"{API_BASE}/subcategories/{cat_id}/", timeout=10)
                if response.status_code == 200:
                    subs = response.json()
                    self.subcategories_map = {sub["name"]: float(sub.get("price", 0)) for sub in subs}
                else:
                    self.subcategories_map = {}
            else:
                self.subcategories_map = {}
                
        except requests.exceptions.ConnectionError:
            logger.warning("Using fallback subcategories due to connection error")
            if text.lower().startswith("t"):
                subs = [{"name": "Cotton T-Shirt", "price": 499}, {"name": "Polo T-Shirt", "price": 699}]
            elif text.lower().startswith("s"):
                subs = [{"name": "Formal Shirt", "price": 899}, {"name": "Casual Shirt", "price": 799}]
            else:
                subs = [{"name": "Regular Jeans", "price": 1299}]
            self.subcategories_map = {sub["name"]: float(sub.get("price", 0)) for sub in subs}
        except Exception as e:
            logger.error(f"Load subcategories failed: {traceback.format_exc()}")
            self.subcategories_map = {}

        self.combo_subcategory.values = ["Select Subcategory"] + list(self.subcategories_map.keys())
        self.combo_subcategory.text = "Select Subcategory"
        self.price_input.text = "0"

    def update_price(self, spinner, text):
        """Update price based on selected subcategory"""
        try:
            price = self.subcategories_map.get(text)
            if price is None:
                self.price_input.text = "0"
            else:
                self.price_input.text = f"{float(price):.2f}"
        except Exception as e:
            logger.error(f"Update price failed: {str(e)}")
            self.price_input.text = "0"

    def validate_customer_info(self):
        """Validate customer information"""
        try:
            # Validate name
            name_valid, name_msg = validate_name(self.entry_name.text)
            if not name_valid:
                self.show_popup("Validation Error", f"Name: {name_msg}")
                return False
            
            # Validate mobile
            mobile_valid, mobile_msg = validate_mobile_number(self.entry_mob.text)
            if not mobile_valid:
                self.show_popup("Validation Error", f"Mobile: {mobile_msg}")
                return False
            
            # Validate email if provided
            if self.entry_email.text.strip():
                email_valid, email_msg = validate_email(self.entry_email.text)
                if not email_valid:
                    self.show_popup("Validation Error", f"Email: {email_msg}")
                    return False
            
            return True
        except Exception as e:
            logger.error(f"Customer validation failed: {str(e)}")
            self.show_popup("Validation Error", "Failed to validate customer information")
            return False

    def validate_product_selection(self):
        """Validate product selection"""
        try:
            if self.combo_category.text == "Select Category":
                self.show_popup("Error", "Please select a category.")
                return False
            
            if self.combo_subcategory.text == "Select Subcategory":
                self.show_popup("Error", "Please select a subcategory.")
                return False
            
            # Validate quantity
            qty_valid, qty_msg = validate_quantity(self.qty_input.text)
            if not qty_valid:
                self.show_popup("Error", f"Quantity: {qty_msg}")
                return False
            
            # Validate price
            price_valid, price_msg = validate_price(self.price_input.text)
            if not price_valid:
                self.show_popup("Error", f"Price: {price_msg}")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Product validation failed: {str(e)}")
            self.show_popup("Error", "Failed to validate product selection")
            return False

    def print_and_save_bill(self, instance):
        """Print bill and automatically save as PDF"""
        try:
            if not self.cart_items:
                self.show_popup("Error", "No items to print. Add items first.")
                return
            
            if not self.validate_customer_info():
                return
            
            subtotal = sum(self.line_totals) if self.line_totals else 0.0
            tax = 0.0
            total = subtotal + tax
            
            if total <= 0:
                self.show_popup("Error", "Total amount must be greater than 0")
                return
            
            # First save the bill as PDF
            bills_dir = os.path.join(os.getcwd(), "Bills")
            os.makedirs(bills_dir, exist_ok=True)
            
            pdf_file = os.path.join(bills_dir, f"Bill_{self.bill_no}.pdf")
            
            generate_receipt_pdf(
                pdf_file,
                self.bill_no,
                self.entry_name.text.strip(),
                self.entry_mob.text.strip(),
                self.entry_email.text.strip(),
                self.cart_items,
                subtotal,
                tax,
                total,
            )
            
            # Then try to print the bill
            img = render_receipt_image_3inch(
                self.bill_no,
                self.entry_name.text.strip(),
                self.entry_mob.text.strip(),
                self.entry_email.text.strip(),
                self.cart_items,
                subtotal,
                tax,
                total,
            )
            
            # Convert to ESC/POS and print
            escpos_data = image_to_escpos_bytes(img)
            sock = connect_to_printer()
            
            # Send in chunks
            chunk_size = 256
            for i in range(0, len(escpos_data), chunk_size):
                sock.send(escpos_data[i:i + chunk_size])
            
            # Paper cut
            sock.send(b'\n')
            sock.send(b'\x1D\x56\x00')
            sock.close()
            
            self.show_popup("Success", f"Bill printed and saved as PDF!\nPDF saved at:\n{pdf_file}")
            
        except RuntimeError as e:
            try:
                # If printing fails, at least the PDF was saved
                self.show_popup("Warning", f"PDF saved but printing failed:\n{str(e)}\n\nPDF saved at:\n{pdf_file}")
            except Exception as ex2:
                self.show_popup("Error", f"Failed to save or print: {str(ex2)}")
        except Exception as e:
            logger.error(f"Print and save bill failed: {traceback.format_exc()}")
            self.show_popup("Error", f"Failed to print and save bill: {str(e)}")

    def handle_print_fallback(self, original_error):
        """Handle print failure (kept for compatibility)"""
        try:
            subtotal = sum(self.line_totals) if self.line_totals else 0.0
            tax = 0.0
            total = subtotal + tax
            
            bills_dir = os.path.join(os.getcwd(), "Bills")
            os.makedirs(bills_dir, exist_ok=True)
            pdf_file = os.path.join(bills_dir, f"Bill_{self.bill_no}.pdf")
            
            generate_receipt_pdf(
                pdf_file,
                self.bill_no,
                self.entry_name.text.strip(),
                self.entry_mob.text.strip(),
                self.entry_email.text.strip(),
                self.cart_items,
                subtotal,
                tax,
                total,
            )
            self.show_popup(
                "Print Failed",
                f"Could not print to Bluetooth printer.\nError: {original_error}\n\nBill saved as PDF at: {pdf_file}"
            )
        except Exception as e:
            logger.error(f"Print fallback failed: {traceback.format_exc()}")
            self.show_popup(
                "Critical Error", 
                f"Printing failed and PDF save also failed:\n{original_error}\n\n{e}"
            )

    def print_bill_with_qr(self, instance):
        """Print bill with QR code (kept for compatibility)"""
        try:
            if not self.cart_items:
                self.show_popup("Error", "No items to print. Add items first.")
                return
            
            if not self.validate_customer_info():
                return
            
            subtotal = sum(self.line_totals) if self.line_totals else 0.0
            tax = 0.0
            total = subtotal + tax
            
            if total <= 0:
                self.show_popup("Error", "Total amount must be greater than 0")
                return
            
            print_with_qr_code(
                self.bill_no,
                self.entry_name.text.strip(),
                self.entry_mob.text.strip(),
                self.cart_items,
                total
            )
            self.show_popup("Success", "✅ Bill printed with QR Code!\nUPI Payment Ready")
            
        except RuntimeError as e:
            try:
                self.print_and_save_bill(instance)
            except Exception as ex2:
                self.handle_print_fallback(ex2)
        except Exception as e:
            logger.error(f"Print with QR failed: {traceback.format_exc()}")
            self.show_popup("Error", f"QR printing failed: {str(e)}")

    def clear_data(self, instance):
        """Clear all data"""
        try:
            self.cart_items.clear()
            self.line_totals.clear()
            self.entry_name.text = ""
            self.entry_mob.text = ""
            self.entry_email.text = ""
            self.combo_category.text = "Select Category"
            self.combo_subcategory.text = "Select Subcategory"
            self.price_input.text = "0"
            self.qty_input.text = "1"
            self.bill_no = str(random.randint(1000, 9999))
            self.refresh_bill_area_header()
            self.update_bill_label_size(self.bill_label, self.bill_label.texture_size)
        except Exception as e:
            logger.error(f"Clear data failed: {str(e)}")
            self.show_popup("Error", "Failed to clear data")

    def show_popup(self, title, message):
        """Show popup message"""
        try:
            popup = Popup(
                title=title, 
                content=Label(text=message, padding=20), 
                size_hint=(None, None), 
                size=(400, 200)
            )
            popup.open()
        except Exception as e:
            logger.error(f"Popup display failed: {str(e)}")
            print(f"{title}: {message}")

class SearchBillsScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "search_bills"
        
        layout = BoxLayout(orientation='vertical', spacing=8, padding=8)
        
        title = Label(text='[b]Search Bills[/b]', markup=True, size_hint_y=None, height=40, font_size=20)
        layout.add_widget(title)
        
        search_layout = GridLayout(cols=2, spacing=8, size_hint_y=None, height=120)
        search_layout.add_widget(Label(text='Bill Number:'))
        self.bill_no_input = TextInput(multiline=False, hint_text='Enter bill number')
        search_layout.add_widget(self.bill_no_input)
        
        search_layout.add_widget(Label(text='Customer Name:'))
        self.customer_name_input = TextInput(multiline=False, hint_text='Enter customer name')
        search_layout.add_widget(self.customer_name_input)
        
        search_layout.add_widget(Label(text='Date (DD-MM-YYYY):'))
        self.date_input = TextInput(multiline=False, hint_text='Enter date')
        search_layout.add_widget(self.date_input)
        
        layout.add_widget(search_layout)
        
        search_btn = Button(text='Search Bills', size_hint_y=None, height=50,
                            background_color=(0.1, 0.6, 0.9, 1))
        search_btn.bind(on_release=self.search_bills)
        layout.add_widget(search_btn)
        
        
        results_scroll = ScrollView(
            size_hint=(1, 1),
            do_scroll_x=False,
            do_scroll_y=True,
            scroll_type=['bars', 'content'],
            bar_width=15,
            bar_color=[0.5, 0.5, 0.5, 0.8],
            bar_inactive_color=[0.5, 0.5, 0.5, 0.3]
        )
        
        self.results_container = BoxLayout(orientation='vertical', size_hint_y=None)
        self.results_container.bind(minimum_height=self.results_container.setter('height'))
        
        self.results_area = TextInput(
            readonly=True, 
            font_size=14, 
            size_hint_y=None,
            multiline=True,
            background_color=(1, 1, 1, 1),
            foreground_color=(0, 0, 0, 1),
            padding=(10, 10)
        )
        self.results_area.bind(text=self.update_results_height)
        
        self.results_container.add_widget(self.results_area)
        results_scroll.add_widget(self.results_container)
        layout.add_widget(results_scroll)
        
        btn_layout = BoxLayout(size_hint_y=None, height=50, spacing=8)
        back_btn = Button(text='Back to Billing', on_release=self.go_back)
        clear_btn = Button(text='Clear Results', on_release=self.clear_results)
        btn_layout.add_widget(back_btn)
        btn_layout.add_widget(clear_btn)
        layout.add_widget(btn_layout)
        
        self.add_widget(layout)

    def update_results_height(self, instance, value):
        """Dynamically update results area height based on content"""
        try:
            line_count = len(self.results_area.text.split('\n'))
            required_height = max(400, line_count * 18)
            self.results_area.height = required_height
            self.results_container.height = required_height
        except Exception as e:
            logger.error(f"Update results height failed: {str(e)}")

    def search_bills(self, instance):
        """Search bills with validation"""
        try:
            bill_no = self.bill_no_input.text.strip()
            customer_name = self.customer_name_input.text.strip()
            date_str = self.date_input.text.strip()
            
           
            if not bill_no and not customer_name and not date_str:
                self.show_popup("Error", "Please enter at least one search criteria.")
                return
            
           
            if bill_no:
                bill_valid, bill_msg = validate_bill_no(bill_no)
                if not bill_valid:
                    self.show_popup("Error", f"Bill number: {bill_msg}")
                    return
            
            
            if customer_name:
                name_valid, name_msg = validate_name(customer_name)
                if not name_valid:
                    self.show_popup("Error", f"Customer name: {name_msg}")
                    return
            
           
            if date_str:
                try:
                    datetime.strptime(date_str, '%d-%m-%Y')
                except ValueError:
                    self.show_popup("Error", "Please enter date in DD-MM-YYYY format.")
                    return
            
           
            params = {}
            if bill_no:
                params['bill_no'] = bill_no
            if customer_name:
                params['customer_name'] = customer_name
            if date_str:
                params['date'] = date_str
            
            headers = {}
            if hasattr(self.manager, 'token') and self.manager.token:
                headers["Authorization"] = f"Token {self.manager.token}"
            
            response = requests.get(f"{API_BASE}/search-bills/", params=params, headers=headers, timeout=15)
            
            if response.status_code == 200:
                bills = response.json()
                self.display_results(bills)
            elif response.status_code == 401:
                self.show_popup("Error", "Session expired. Please login again.")
                self.go_back(None)
            else:
                self.show_popup("Error", f"Failed to search bills: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            self.show_popup("Error", "Cannot connect to server.")
        except requests.exceptions.Timeout:
            self.show_popup("Error", "Search request timed out.")
        except Exception as e:
            logger.error(f"Search bills failed: {traceback.format_exc()}")
            self.show_popup("Error", f"Search failed: {str(e)}")

    def display_results(self, bills):
        """Display search results"""
        try:
            if not bills:
                self.results_area.text = "No bills found matching your criteria."
                return
            
            if not isinstance(bills, list):
                self.results_area.text = "Invalid response format from server."
                return
            
            result_text = f"Found {len(bills)} bill(s):\n\n"
            result_text += "="*80 + "\n"
            
            for bill in bills:
                if not isinstance(bill, dict):
                    continue
                    
                result_text += f"Bill No: {bill.get('bill_no', 'N/A')}\n"
                result_text += f"Customer: {bill.get('customer_name', 'N/A')}\n"
                result_text += f"Mobile: {bill.get('customer_mobile', 'N/A')}\n"
                result_text += f"Date: {bill.get('created_at', 'N/A')}\n"
                result_text += f"Total: ₹{bill.get('total', 0):.2f}\n"
                
                items = bill.get('items', [])
                if items and isinstance(items, list):
                    result_text += "Items:\n"
                    for item in items:
                        if isinstance(item, dict):
                            result_text += f"  - {item.get('product_name', 'N/A')} "
                            result_text += f"(Qty: {item.get('quantity', 0)}, "
                            result_text += f"Price: ₹{item.get('price', 0):.2f})\n"
                
                result_text += "="*80 + "\n\n"
            
            self.results_area.text = result_text
            self.update_results_height(self.results_area, self.results_area.text)
        except Exception as e:
            logger.error(f"Display results failed: {str(e)}")
            self.results_area.text = "Error displaying results."

    def clear_results(self, instance):
        """Clear search results"""
        try:
            self.results_area.text = ""
            self.bill_no_input.text = ""
            self.customer_name_input.text = ""
            self.date_input.text = ""
            self.update_results_height(self.results_area, self.results_area.text)
        except Exception as e:
            logger.error(f"Clear results failed: {str(e)}")
            self.show_popup("Error", "Failed to clear results")

    def go_back(self, instance):
        """Go back to billing screen"""
        try:
            self.manager.transition.direction = "right"
            self.manager.current = "billing"
        except Exception as e:
            logger.error(f"Go back failed: {str(e)}")
            self.show_popup("Error", "Navigation failed")

    def show_popup(self, title, message):
        """Safe popup display"""
        try:
            Popup(title=title, content=Label(text=message), size_hint=(0.6, 0.4)).open()
        except Exception as e:
            logger.error(f"Popup failed: {str(e)}")
            print(f"{title}: {message}")

class ProductManagementScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.name = "products"
        
    def on_enter(self):
        """Build UI when screen is entered"""
        try:
            self.build_ui()
        except Exception as e:
            self.show_popup("Error", "Failed to load product management")

    def build_ui(self):
        """Build the product management UI with compact search"""
        try:
            self.clear_widgets()

            # Main container with vertical layout
            main = BoxLayout(orientation='vertical', padding=10, spacing=10)

            # TOP BAR: Title + Search in one line
            top_bar = BoxLayout(
                orientation='horizontal',
                size_hint_y=None,
                height=60,
                spacing=10,
                padding=(0, 0, 0, 5)
            )
            
            # Title on left
            title_label = Label(
                text="[b]Products Management[/b]",
                markup=True,
                font_size=32,
                color=(0, 0, 0, 1),
                size_hint_x=0.4,
                halign='left',
                valign='middle',
                bold = True
            )
            title_label.bind(size=title_label.setter('text_size'))
            
            # Compact search area on right
            search_area = BoxLayout(
                orientation='horizontal',
                size_hint_x=0.6,
                spacing=5,
                padding=(5, 0, 0, 0)
            )
            
            # Compact search input
            self.search_input = TextInput(
                hint_text="Search products...",
                multiline=False,
                size_hint_x=0.7,
                font_size=22,
                height=40,
                padding=[10, 10, 10, 10],
                halign='left'
            )
            
            # Search button with icon
            search_btn = Button(
                text="Search",
                size_hint_x=0.15,
                background_color=(0.1, 0.6, 0.9, 1),
                color=(1, 1, 1, 1),
                font_size=22,
                padding=[5, 5]
            )
            search_btn.bind(on_release=self.search_products)
            
            # Clear button
            clear_search_btn = Button(
                text="Clear",
                size_hint_x=0.15,
                background_color=(0.8, 0.3, 0.3, 1),
                color=(1, 1, 1, 1),
                font_size=22,
                padding=[5, 5]
            )
            clear_search_btn.bind(on_release=self.clear_search)
            
            search_area.add_widget(self.search_input)
            search_area.add_widget(search_btn)
            search_area.add_widget(clear_search_btn)
            
            top_bar.add_widget(title_label)
            top_bar.add_widget(search_area)
            main.add_widget(top_bar)

            # Product list container
            product_container = BoxLayout(orientation='vertical', spacing=5)
            
            # Product list header
            header = BoxLayout(
                orientation='horizontal',
                size_hint_y=None,
                height=60,
                padding=[15, 5, 15, 5]
            )
            
            with header.canvas.before:
                Color(0.9, 0.9, 0.9, 1)
                header.rect = Rectangle(size=header.size, pos=header.pos)
            header.bind(size=self.update_header_rect, pos=self.update_header_rect)
            
            # Header labels
            header.add_widget(Label(
                text="[b]Product Name[/b]",
                markup=True,
                color=(0.2, 0.2, 0.2, 1),
                font_size=26,
                size_hint_x=0.4,
                halign='left',
                valign='middle',
                bold =True
            ))
            
            header.add_widget(Label(
                text="[b]Price[/b]",
                markup=True,
                color=(0.2, 0.2, 0.2, 1),
                font_size=26,
                size_hint_x=0.3,
                halign='left',
                valign='middle',
                bold =True
            ))
            
            header.add_widget(Label(
                text="[b]Actions[/b]",
                markup=True,
                color=(0.2, 0.2, 0.2, 1),
                font_size=26,
                size_hint_x=0.3,
                halign='center',
                valign='middle',
                bold =True
            ))
            
            product_container.add_widget(header)
            
            # Scrollable product list
            scroll = ScrollView(size_hint=(1, 1))

            self.container = BoxLayout(
                orientation='vertical',
                spacing=2,
                padding=[5, 5, 5, 5],
                size_hint_y=None
            )
            self.container.bind(minimum_height=self.container.setter('height'))

            scroll.add_widget(self.container)
            product_container.add_widget(scroll)
            
            main.add_widget(product_container)

            # Bottom buttons
            bottom_bar = BoxLayout(
                size_hint_y=None,
                height=60,
                spacing=15,
                padding=[20, 5, 20, 5]
            )
            
            # Add new product button
            add_btn = Button(
                text="Add Product",
                size_hint_x=0.5,
                background_color=(0.2, 0.8, 0.2, 1),
                color=(1, 1, 1, 1),
                font_size=22,
                bold=True,
                padding=[10, 10]
            )
            add_btn.bind(on_release=self.open_add_popup)
            
            # Back button
            back_btn = Button(
                text="Back",
                size_hint_x=0.5,
                background_color=(1.0, 0.65, 0.0, 1),
                color=(1, 1, 1, 1),
                font_size=22,
                padding=[10, 10]
            )
            back_btn.bind(on_release=self.go_back)
            
            bottom_bar.add_widget(add_btn)
            bottom_bar.add_widget(back_btn)
            
            main.add_widget(bottom_bar)

            self.add_widget(main)
            self.load_products()
            
        except Exception as e:
            self.show_popup("Error", f"Failed to build product management UI: {str(e)}")

    def update_header_rect(self, instance, value):
        """Update header rectangle"""
        try:
            instance.rect.pos = instance.pos
            instance.rect.size = instance.size
        except Exception as e:
            pass

    def get_auth_headers(self):
        """Get authentication headers with token"""
        headers = {
            'Content-Type': 'application/json'
        }
        if hasattr(self.manager, 'token') and self.manager.token:
            headers["Authorization"] = f"Token {self.manager.token}"
        return headers

    def load_products(self, products_list=None):
        """Load products from API with authentication or display given list"""
        try:
            self.container.clear_widgets()

            if products_list is not None:
                self.display_products_list(products_list)
                return
                
            try:
                headers = self.get_auth_headers()
                response = requests.get(f"{API_BASE}/products/", headers=headers, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    if not isinstance(data, list):
                        data = []
                    self.display_products_list(data)
                elif response.status_code == 401:
                    self.show_popup("Error", "Session expired. Please login again.")
                    self.go_back(None)
                    return
                else:
                    data = []
                    self.display_products_list(data)
                    self.show_popup("Warning", f"Failed to load products: {response.status_code}")
            except requests.exceptions.ConnectionError:
                data = []
                self.display_products_list(data)
                self.show_popup("Warning", "Cannot connect to server. Using empty product list.")
            except Exception as e:
                logger.error(f"API call failed: {str(e)}")
                data = []
                self.display_products_list(data)

        except Exception as e:
            self.show_popup("Error", "Failed to load products")

    def display_products_list(self, data, search_query=None):
        """Display a list of products in the container"""
        try:
            self.container.clear_widgets()
            
            if search_query:
                # Add search results header
                results_header = BoxLayout(
                    orientation='horizontal',
                    size_hint_y=None,
                    height=50,
                    padding=[15, 5, 15, 5]
                )
                
                with results_header.canvas.before:
                    Color(0.8, 0.9, 1, 1)  # Light blue background
                    results_header.rect = Rectangle(size=results_header.size, pos=results_header.pos)
                
                results_label = Label(
                    text=f"Search Results for '{search_query}': {len(data)} found",
                    color=(0.1, 0.3, 0.6, 1),
                    font_size=22,
                    bold=True,
                    size_hint_x=1,
                    halign='left',
                    valign='middle'
                )
                results_label.bind(size=results_label.setter('text_size'))
                results_header.add_widget(results_label)
                self.container.add_widget(results_header)
                
                results_header.bind(size=self.update_rect, pos=self.update_rect)
            
            if not data:
                no_data_label = BoxLayout(
                    orientation='vertical',
                    size_hint_y=None,
                    height=200,
                    padding=[20, 20, 20, 20]
                )
                if search_query:
                    icon_text = "🔍"
                    message = f"No products found for '{search_query}'"
                    sub_message = "Try a different search term"
                else:
                    icon_text = "📦"
                    message = "No products found"
                    sub_message = "Add your first product using the + button below"
                
                no_data_label.add_widget(Label(
                    text=icon_text,
                    font_size=48,
                    color=(0.7, 0.7, 0.7, 1)
                ))
                no_data_label.add_widget(Label(
                    text=message,
                    color=(0.5, 0.5, 0.5, 1),
                    font_size=18
                ))
                no_data_label.add_widget(Label(
                    text=sub_message,
                    color=(0.6, 0.6, 0.6, 1),
                    font_size=14
                ))
                self.container.add_widget(no_data_label)
                return

            for idx, product in enumerate(data):
                if not isinstance(product, dict):
                    continue
                    
                card = BoxLayout(
                    orientation='horizontal',
                    size_hint_y=None,
                    height=55,
                    padding=[15, 5, 15, 5],
                    spacing=10
                )

                # Alternating background colors for rows
                with card.canvas.before:
                    if idx % 2 == 0:
                        Color(0.95, 0.95, 0.95, 1)  # Light gray
                    else:
                        Color(1, 1, 1, 1)  # White
                    card.rect = Rectangle(size=card.size, pos=card.pos)

                card.bind(size=self.update_rect, pos=self.update_rect)

                # Product name
                name_label = Label(
                    text=product.get("name", "Unnamed"),
                    color=(0.1, 0.1, 0.1, 1),
                    font_size=22,
                    size_hint_x=0.4,
                    halign='center',
                    valign='middle'
                )
                name_label.bind(size=name_label.setter('text_size'))
                card.add_widget(name_label)

                # Price
                price = product.get('price', 0)
                if isinstance(price, str):
                    try:
                        price = float(price)
                    except:
                        price = 0
                price_label = Label(
                    text=f"                                                ₹{float(price):.2f}",
                    color=(0.1, 0.5, 0.1, 1),
                    font_size=22,
                    bold=True,
                    size_hint_x=0.3,
                    halign='left',
                    valign='middle'
                )
                price_label.bind(size=price_label.setter('text_size'))
                card.add_widget(price_label)

                # Action buttons in a horizontal layout
                action_buttons = BoxLayout(
                    orientation='horizontal',
                    size_hint_x=0.3,
                    spacing=5
                )
                
                # Edit button
                edit_btn = Button(
                    text="Edit",
                    size_hint_x=0.5,
                    background_color=(0.30, 0.80, 0.45, 0.9),
                    color=(1, 1, 1, 1),
                    font_size=20,
                    bold=True,
                    padding=[5, 5]
                )
                edit_btn.bind(on_release=lambda x, p=product: self.edit_product(p.get("id")))
                action_buttons.add_widget(edit_btn)

                # Delete button
                del_btn = Button(
                    text="Delete",
                    size_hint_x=0.5,
                    background_color=(0.85, 0.30, 0.30, 0.9),
                    color=(1, 1, 1, 1),
                    font_size=20,
                    bold=True,
                    padding=[5, 5]
                )
                del_btn.bind(on_release=lambda x, p=product: self.delete_product(p.get("id")))
                action_buttons.add_widget(del_btn)

                card.add_widget(action_buttons)
                self.container.add_widget(card)
                
        except Exception as e:
            self.container.add_widget(Label(
                text="Error displaying products",
                color=(1, 0, 0, 1),
                font_size=16
            ))

    def update_rect(self, instance, value):
        """Update card rectangle"""
        try:
            instance.rect.pos = instance.pos
            instance.rect.size = instance.size
        except Exception as e:
            pass

    def go_back(self, instance=None):
        """Go back to billing screen"""
        try:
            self.manager.transition.direction = "right"
            self.manager.current = "billing"
        except Exception as e:
            self.show_popup("Error", "Navigation failed")

    def open_add_popup(self, instance):
        """Open popup to add new product"""
        try:
            box = BoxLayout(orientation="vertical", spacing=10, padding=[15, 15, 15, 15])
            
            # Product Name
            self.pname = TextInput(
                hint_text="Product Name", 
                multiline=False,
                size_hint_y=None,
                height=50,
                padding=[10, 10, 10, 10],
                font_size=16
            )
            box.add_widget(Label(text="Product Name:", size_hint_y=None, height=30))
            box.add_widget(self.pname)
            
            # Category
            category_layout = BoxLayout(orientation='horizontal', spacing=10, size_hint_y=None, height=50)
            category_layout.add_widget(Label(text="Category:", size_hint_x=0.4))
            
            self.category_spinner = Spinner(
                text='Select Category',
                values=['Shirts', 'T-Shirts', 'Pants'],
                size_hint_x=0.6,
                font_size=16
            )
            category_layout.add_widget(self.category_spinner)
            box.add_widget(category_layout)
            
            # Price
            self.pprice = TextInput(
                hint_text="Price (e.g., 100.00)", 
                multiline=False,
                size_hint_y=None,
                height=50,
                padding=[10, 10, 10, 10],
                font_size=16
            )
            box.add_widget(Label(text="Price (₹):", size_hint_y=None, height=30))
            box.add_widget(self.pprice)
            
            # Buttons
            btn_layout = BoxLayout(size_hint_y=None, height=60, spacing=10)
            
            save_btn = Button(
                text="Save",
                background_color=(0.1, 0.5, 0.8, 1),
                color=(1, 1, 1, 1),
                font_size=20,
                padding=[10, 10]
            )
            
            cancel_btn = Button(
                text="Cancel",
                background_color=(0.8, 0.2, 0.2, 1),
                color=(1, 1, 1, 1),
                font_size=20,
                padding=[10, 10]
            )
            
            save_btn.bind(on_release=self.add_product)
            cancel_btn.bind(on_release=lambda x: self.popup.dismiss())
            
            btn_layout.add_widget(save_btn)
            btn_layout.add_widget(cancel_btn)
            box.add_widget(btn_layout)

            self.popup = Popup(
                title="Add New Product", 
                content=box, 
                size_hint=(0.6, 0.6),
                auto_dismiss=False
            )
            self.popup.open()
            
        except Exception as e:
            self.show_popup("Error", "Failed to open add product form")

    def add_product(self, instance):
        """Add new product to the database"""
        try:
            name = self.pname.text.strip()
            price_str = self.pprice.text.strip()
            category_name = self.category_spinner.text
            
            # Validation
            if not name:
                self.show_popup("Error", "Product name is required")
                return
            
            if not price_str:
                self.show_popup("Error", "Price is required")
                return
            
            if category_name == "Select Category":
                self.show_popup("Error", "Please select a category")
                return
            
            try:
                price = float(price_str)
                if price <= 0:
                    self.show_popup("Error", "Price must be greater than 0")
                    return
            except ValueError:
                self.show_popup("Error", "Price must be a valid number (e.g., 100.50)")
                return
            
            # Map category name to ID
            category_map = {
                "Shirts": 1,
                "T-Shirts": 2, 
                "Pants": 3,
            }
            
            category_id = category_map.get(category_name)
            if not category_id:
                self.show_popup("Error", "Invalid category selected")
                return
            
            # Prepare data
            data = {
                "category": category_id,
                "name": name,
                "price": price
            }
            
            # Send request
            headers = self.get_auth_headers()
            response = requests.post(
                f"{API_BASE}/products/", 
                json=data, 
                headers=headers, 
                timeout=15
            )
            
            if response.status_code in [200, 201]:
                self.show_popup("Success", f"Product '{name}' added successfully!")
                self.popup.dismiss()
                self.load_products()
            elif response.status_code == 401:
                self.show_popup("Error", "Session expired. Please login again.")
                self.popup.dismiss()
                self.go_back()
            else:
                self.show_popup("Error", f"Failed to add product: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            self.show_popup("Error", "Cannot connect to server.")
        except Exception as e:
            self.show_popup("Error", f"Failed to add product: {str(e)}")

    def edit_product(self, product_id):
        """Edit existing product"""
        try:
            if not product_id:
                self.show_popup("Error", "Invalid product ID")
                return
            
            headers = self.get_auth_headers()
            response = requests.get(f"{API_BASE}/products/{product_id}/", headers=headers, timeout=10)
            
            if response.status_code == 200:
                product = response.json()
                self.open_edit_popup(product_id, product)
            elif response.status_code == 401:
                self.show_popup("Error", "Session expired. Please login again.")
                self.go_back()
            else:
                self.show_popup("Error", f"Failed to load product: {response.status_code}")
        except Exception as e:
            self.show_popup("Error", f"Failed to edit product: {str(e)}")

    def open_edit_popup(self, product_id, product):
        """Open popup to edit product"""
        try:
            box = BoxLayout(orientation="vertical", spacing=10, padding=[15, 15, 15, 15])
            
            # Product Name
            self.edit_pname = TextInput(
                text=product.get("name", ""), 
                multiline=False,
                size_hint_y=None,
                height=50,
                padding=[10, 10, 10, 10],
                font_size=20
            )
            box.add_widget(Label(text="Product Name:", size_hint_y=None, height=35))
            box.add_widget(self.edit_pname)
            
            # Category
            category_layout = BoxLayout(orientation='horizontal', spacing=10, size_hint_y=None, height=50)
            category_layout.add_widget(Label(text="Category:", size_hint_x=0.4))
            
            current_category_id = product.get("category", 1)
            category_id_to_name = {
                1: "Shirts",
                2: "T-Shirts", 
                3: "Pants",
            }
            current_category_name = category_id_to_name.get(current_category_id, "Shirts")
            
            self.edit_category_spinner = Spinner(
                text=current_category_name,
                values=['Shirts', 'T-Shirts', 'Pants'],
                size_hint_x=0.6,
                font_size=20
            )
            category_layout.add_widget(self.edit_category_spinner)
            box.add_widget(category_layout)
            
            # Price
            price = product.get("price", 0)
            if isinstance(price, str):
                price_display = price
            else:
                price_display = str(float(price))
            
            self.edit_pprice = TextInput(
                text=price_display, 
                multiline=False,
                size_hint_y=None,
                height=50,
                padding=[10, 10, 10, 10],
                font_size=20
            )
            box.add_widget(Label(text="Price (₹):", size_hint_y=None, height=30))
            box.add_widget(self.edit_pprice)
            
            # Buttons
            btn_layout = BoxLayout(size_hint_y=None, height=60, spacing=10)
            
            update_btn = Button(
                text="Update",
                background_color=(0.1, 0.5, 0.8, 1),
                color=(1, 1, 1, 1),
                font_size=20,
                padding=[10, 10]
            )
            
            cancel_btn = Button(
                text="Cancel",
                background_color=(0.8, 0.2, 0.2, 1),
                color=(1, 1, 1, 1),
                font_size=20,
                padding=[10, 10]
            )
            
            update_btn.bind(on_release=lambda x: self.update_product(product_id))
            cancel_btn.bind(on_release=lambda x: self.edit_popup.dismiss())
            
            btn_layout.add_widget(update_btn)
            btn_layout.add_widget(cancel_btn)
            box.add_widget(btn_layout)

            self.edit_popup = Popup(
                title="Edit Product", 
                content=box, 
                size_hint=(0.6, 0.6),
                auto_dismiss=False
            )
            self.edit_popup.open()
            
        except Exception as e:
            self.show_popup("Error", "Failed to open edit form")

    def update_product(self, product_id):
        """Update product in database"""
        try:
            name = self.edit_pname.text.strip()
            price_str = self.edit_pprice.text.strip()
            category_name = self.edit_category_spinner.text
            
            # Validation
            if not name:
                self.show_popup("Error", "Product name is required")
                return
            
            if not price_str:
                self.show_popup("Error", "Price is required")
                return
            
            try:
                price = float(price_str)
                if price <= 0:
                    self.show_popup("Error", "Price must be greater than 0")
                    return
            except ValueError:
                self.show_popup("Error", "Price must be a valid number")
                return
            
            # Map category name to ID
            category_map = {
                "Shirts": 1,
                "T-Shirts": 2, 
                "Pants": 3,
            }
            
            category_id = category_map.get(category_name, 1)
            
            # Prepare data
            data = {
                "category": category_id,
                "name": name,
                "price": price
            }
            
            # Send request
            headers = self.get_auth_headers()
            response = requests.put(
                f"{API_BASE}/products/{product_id}/", 
                json=data, 
                headers=headers, 
                timeout=15
            )
            
            if response.status_code == 200:
                self.show_popup("Success", "Product updated successfully!")
                self.edit_popup.dismiss()
                self.load_products()
            elif response.status_code == 401:
                self.show_popup("Error", "Session expired. Please login again.")
                self.edit_popup.dismiss()
                self.go_back()
            else:
                self.show_popup("Error", f"Failed to update product: {response.status_code}")
                
        except Exception as e:
            self.show_popup("Error", f"Failed to update product: {str(e)}")

    def delete_product(self, product_id):
        """Delete product with confirmation"""
        try:
            # Create confirmation popup
            box = BoxLayout(orientation='vertical', spacing=10, padding=[20, 20, 20, 20])
            
            box.add_widget(Label(
                text="Are you sure you want to delete this product?\nThis action cannot be undone.",
                font_size=20
            ))
            
            btn_layout = BoxLayout(size_hint_y=None, height=55, spacing=10)
            
            confirm_btn = Button(
                text='Delete',
                background_color=(0.8, 0, 0, 1),
                color=(1, 1, 1, 1)
            )
            
            cancel_btn = Button(
                text='Cancel',
                background_color=(0.5, 0.5, 0.5, 1),
                color=(1, 1, 1, 1)
            )
            
            confirm_btn.bind(on_release=lambda x: self.perform_delete(product_id, popup))
            cancel_btn.bind(on_release=lambda x: popup.dismiss())
            
            btn_layout.add_widget(confirm_btn)
            btn_layout.add_widget(cancel_btn)
            box.add_widget(btn_layout)
            
            popup = Popup(
                title="Confirm Delete",
                content=box,
                size_hint=(0.6, 0.4)
            )
            popup.open()
            
        except Exception as e:
            self.show_popup("Error", "Failed to confirm deletion")

    def perform_delete(self, product_id, popup_instance):
        """Actually delete the product"""
        try:
            headers = self.get_auth_headers()
            response = requests.delete(
                f"{API_BASE}/products/{product_id}/", 
                headers=headers, 
                timeout=15
            )
            
            if response.status_code in [200, 204]:
                self.show_popup("Success", "Product deleted successfully!")
                popup_instance.dismiss()
                self.load_products()
            elif response.status_code == 401:
                self.show_popup("Error", "Session expired. Please login again.")
                popup_instance.dismiss()
                self.go_back()
            else:
                self.show_popup("Error", f"Failed to delete product: {response.status_code}")
                
        except Exception as e:
            self.show_popup("Error", f"Failed to delete product: {str(e)}")

    def search_products(self, instance):
        """Search products by name or category"""
        try:
            search_query = self.search_input.text.strip()
            
            if not search_query:
                self.load_products()  # Show all products if search is empty
                return
            
            # Perform search
            self.perform_search(search_query)
            
        except Exception as e:
            self.show_popup("Error", f"Search failed: {str(e)}")

    def perform_search(self, search_query):
        """Perform the actual search"""
        try:
            headers = self.get_auth_headers()
            
            try:
                response = requests.get(f"{API_BASE}/products/", headers=headers, timeout=10)
                
                if response.status_code == 200:
                    all_products = response.json()
                    if not isinstance(all_products, list):
                        all_products = []
                else:
                    self.show_popup("Error", f"Failed to load products: {response.status_code}")
                    return
            except requests.exceptions.ConnectionError:
                self.show_popup("Error", "Cannot connect to server")
                return
            
            # Filter products
            filtered_products = []
            for product in all_products:
                if not isinstance(product, dict):
                    continue
                    
                product_name = product.get("name", "").lower()
                category_id = product.get("category")
                category_map = {
                    1: "shirts",
                    2: "t-shirts", 
                    3: "pants",
                }
                category_name = category_map.get(category_id, "").lower()
                
                if (search_query.lower() in product_name) or (search_query.lower() in category_name):
                    filtered_products.append(product)
            
            # Display filtered products with search query
            self.display_products_list(filtered_products, search_query)
            
        except Exception as e:
            self.show_popup("Error", f"Search failed: {str(e)}")

    def clear_search(self, instance):
        """Clear search and show all products"""
        try:
            self.search_input.text = ""
            self.search_input.hint_text = "Search products..."
            self.load_products()
        except Exception as e:
            self.show_popup("Error", "Failed to clear search")

    def show_popup(self, title, message):
        """Safe popup display"""
        try:
            Popup(title=title, content=Label(text=message), size_hint=(0.6, 0.4)).open()
        except Exception as e:
            print(f"{title}: {message}")

class BillingApp(App):
    def build(self):
        """Build the main application"""
        try:
            Window.clearcolor = (1, 1, 1, 1)
            sm = ScreenManager(transition=SlideTransition())
            sm.token = None
            
           
            screens = [
                LoginScreen(),
                ForgotPasswordScreen(),
                ChangePasswordScreen(),
                BillingScreen(),
                SearchBillsScreen(),
                ProductManagementScreen()
            ]
            
            for screen in screens:
                sm.add_widget(screen)
            
            return sm
        except Exception as e:
            logger.error(f"App build failed: {traceback.format_exc()}")
            layout = BoxLayout(orientation='vertical')
            layout.add_widget(Label(text="Fatal Error", font_size=24, color=(1,0,0,1)))
            layout.add_widget(Label(text=str(e)))
            return layout

    def on_stop(self):
        """Cleanup when app stops"""
        logger.info("Application stopped")

if __name__ == "__main__":
    try:
        print("Starting ELEVEN-7 Billing Application...")
        print("=" * 50)      
        app = BillingApp()
        app.run()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        logger.error(f"Fatal application error: {traceback.format_exc()}")
        print(f"Fatal error: {str(e)}")
        print("Check billing_app_errors.log for details")
