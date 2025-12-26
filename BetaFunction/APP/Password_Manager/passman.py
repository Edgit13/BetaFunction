import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import json
import os
import hashlib
import base64
from cryptography.fernet import Fernet
import pyperclip
import threading
import time
import sqlite3
import shutil
from pathlib import Path
import sys
import csv
import webbrowser

# Conditional imports for Windows-specific features
try:
    import win32crypt

    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("Note: Windows-specific features (browser password import) are not available on this platform.")


class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager Pro")
        self.root.geometry("800x600")

        # Set minimum window size
        self.root.minsize(700, 500)

        # Create data directory if it doesn't exist
        self.data_dir = "password_manager_data"
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        # Update file paths to use data directory
        self.data_file = os.path.join(self.data_dir, "passwords.json")
        self.key_file = os.path.join(self.data_dir, "key.key")
        self.master_password_file = os.path.join(self.data_dir, "master.hash")
        self.backup_dir = os.path.join(self.data_dir, "backups")

        self.cipher = None
        self.passwords = {}
        self.clipboard_monitor_active = False
        self.last_clipboard = ""
        self.tree = None
        self.status_var = None
        self.master_btn = None
        self.search_var = None
        self.monitor_thread = None
        self.context_menu = None

        # Set window icon (optional)
        try:
            self.root.iconbitmap('icon.ico')  # You can create an icon file
        except:
            pass

        # Check if first run
        if not os.path.exists(self.master_password_file):
            self.setup_master_password()
        else:
            self.login()

    def setup_master_password(self):
        """Setup master password on first run"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Setup Master Password")
        dialog.geometry("400x250")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        tk.Label(dialog, text="Create Master Password",
                 font=("Arial", 14, "bold")).pack(pady=(20, 10))

        tk.Label(dialog, text="Password must be at least 8 characters",
                 font=("Arial", 10)).pack(pady=(0, 10))

        tk.Label(dialog, text="Enter Master Password:",
                 font=("Arial", 11)).pack(anchor=tk.W, padx=40)
        password_entry = tk.Entry(dialog, show="*", font=("Arial", 12))
        password_entry.pack(pady=5, padx=40, fill=tk.X)

        tk.Label(dialog, text="Confirm Password:",
                 font=("Arial", 11)).pack(anchor=tk.W, padx=40)
        confirm_entry = tk.Entry(dialog, show="*", font=("Arial", 12))
        confirm_entry.pack(pady=5, padx=40, fill=tk.X)

        def save_master():
            password = password_entry.get()
            confirm = confirm_entry.get()

            if password != confirm:
                messagebox.showerror("Error", "Passwords don't match!")
                return

            if len(password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters!")
                return

            # Check password strength
            if not self.check_password_strength(password):
                if not messagebox.askyesno("Weak Password",
                                           "Your password may be weak. Do you want to use it anyway?"):
                    return

            # Save master password hash with salt
            salt = os.urandom(32)
            pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

            with open(self.master_password_file, 'wb') as f:
                f.write(salt + pwd_hash)

            # Generate encryption key
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)

            self.cipher = Fernet(key)

            # Initialize with empty passwords
            self.save_passwords()

            # Create backup directory
            if not os.path.exists(self.backup_dir):
                os.makedirs(self.backup_dir)

            dialog.destroy()
            self.show_main_window()

        def check_password_strength_visual():
            password = password_entry.get()
            strength = self.get_password_strength(password)

            # Update password strength indicator
            strength_label.config(text=f"Strength: {strength}")

            # Update color based on strength
            if strength == "Weak":
                strength_label.config(fg="red")
            elif strength == "Medium":
                strength_label.config(fg="orange")
            else:
                strength_label.config(fg="green")

        strength_label = tk.Label(dialog, text="Strength: ", font=("Arial", 10))
        strength_label.pack(pady=5)

        password_entry.bind('<KeyRelease>', lambda e: check_password_strength_visual())

        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=15)

        tk.Button(btn_frame, text="Create", command=save_master, font=("Arial", 11),
                  bg="#4CAF50", fg="white", padx=20).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=sys.exit, font=("Arial", 11),
                  bg="#f44336", fg="white", padx=20).pack(side=tk.LEFT, padx=10)

        # Set focus and bind Enter key
        password_entry.focus_set()
        password_entry.bind('<Return>', lambda e: confirm_entry.focus_set())
        confirm_entry.bind('<Return>', lambda e: save_master())

        dialog.wait_window()

    def check_password_strength(self, password):
        """Check password strength"""
        if len(password) < 8:
            return False

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        # At least 3 of the 4 criteria
        return sum([has_upper, has_lower, has_digit, has_special]) >= 3

    def get_password_strength(self, password):
        """Get password strength rating"""
        if len(password) < 8:
            return "Weak"

        score = 0
        if len(password) >= 12:
            score += 1
        if any(c.isupper() for c in password) and any(c.islower() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(not c.isalnum() for c in password):
            score += 1

        if score >= 3:
            return "Strong"
        elif score >= 2:
            return "Medium"
        else:
            return "Weak"

    def login(self):
        """Login with master password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Login")
        dialog.geometry("350x180")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        # Center the dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        tk.Label(dialog, text="Enter Master Password:",
                 font=("Arial", 12)).pack(pady=(20, 5))

        password_entry = tk.Entry(dialog, show="*", font=("Arial", 12))
        password_entry.pack(pady=5, padx=20, fill=tk.X)

        def check_password():
            password = password_entry.get()

            try:
                with open(self.master_password_file, 'rb') as f:
                    data = f.read()

                salt = data[:32]
                stored_hash = data[32:]

                pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

                if pwd_hash == stored_hash:
                    with open(self.key_file, 'rb') as f:
                        key = f.read()
                    self.cipher = Fernet(key)
                    self.load_passwords()
                    dialog.destroy()
                    self.show_main_window()
                else:
                    messagebox.showerror("Error", "Incorrect password!")
                    password_entry.delete(0, tk.END)
                    password_entry.focus_set()

            except Exception as e:
                messagebox.showerror("Error", f"Login failed: {str(e)}")

        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=15)

        tk.Button(btn_frame, text="Login", command=check_password, font=("Arial", 11),
                  bg="#4CAF50", fg="white", padx=20).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=sys.exit, font=("Arial", 11),
                  bg="#f44336", fg="white", padx=20).pack(side=tk.LEFT, padx=10)

        # Bind Enter key
        password_entry.focus_set()
        password_entry.bind('<Return>', lambda e: check_password())

        dialog.wait_window()

    def show_main_window(self):
        """Display main password manager interface"""
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Main container
        main_container = tk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Top frame with buttons
        top_frame = tk.Frame(main_container)
        top_frame.pack(fill=tk.X, pady=(0, 10))

        button_config = {
            "font": ("Arial", 10),
            "padx": 12,
            "pady": 6
        }

        tk.Button(top_frame, text="➕ Add Password", command=self.add_password,
                  bg="#4CAF50", fg="white", **button_config).pack(side=tk.LEFT, padx=2)
        tk.Button(top_frame, text="✏️ Edit", command=self.edit_password,
                  bg="#2196F3", fg="white", **button_config).pack(side=tk.LEFT, padx=2)
        tk.Button(top_frame, text="🗑️ Delete", command=self.delete_password,
                  bg="#f44336", fg="white", **button_config).pack(side=tk.LEFT, padx=2)
        tk.Button(top_frame, text="🌐 Import Browser", command=self.import_from_browser,
                  bg="#9C27B0", fg="white", **button_config).pack(side=tk.LEFT, padx=2)
        tk.Button(top_frame, text="📤 Export CSV", command=self.export_csv,
                  bg="#FF9800", fg="white", **button_config).pack(side=tk.LEFT, padx=2)
        tk.Button(top_frame, text="💾 Backup", command=self.create_backup,
                  bg="#009688", fg="white", **button_config).pack(side=tk.LEFT, padx=2)

        # Single toggle button for monitoring
        self.monitor_btn = tk.Button(top_frame, text="🔍 Start Monitor",
                                     command=self.toggle_monitoring,
                                     bg="#2196F3", fg="white", **button_config)
        self.monitor_btn.pack(side=tk.LEFT, padx=2)

        # Search frame
        search_frame = tk.Frame(main_container)
        search_frame.pack(fill=tk.X, pady=(0, 10))

        tk.Label(search_frame, text="🔍 Search:", font=("Arial", 11)).pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace('w', self.filter_passwords)
        search_entry = tk.Entry(search_frame, textvariable=self.search_var,
                                font=("Arial", 11), width=30)
        search_entry.pack(side=tk.LEFT, padx=5)

        # Clear search button
        tk.Button(search_frame, text="Clear", command=self.clear_search,
                  font=("Arial", 9), padx=8).pack(side=tk.LEFT, padx=5)

        # Password list frame
        list_frame = tk.Frame(main_container)
        list_frame.pack(fill=tk.BOTH, expand=True)

        # Create Treeview with scrollbar
        tree_frame = tk.Frame(list_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        # Create scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")

        self.tree = ttk.Treeview(tree_frame,
                                 columns=("Website", "Username", "Password"),
                                 show="headings",
                                 yscrollcommand=vsb.set,
                                 xscrollcommand=hsb.set,
                                 selectmode="browse")

        # Configure columns
        self.tree.heading("Website", text="Website", anchor=tk.W)
        self.tree.heading("Username", text="Username", anchor=tk.W)
        self.tree.heading("Password", text="Password", anchor=tk.W)

        self.tree.column("Website", width=250, minwidth=150)
        self.tree.column("Username", width=250, minwidth=150)
        self.tree.column("Password", width=200, minwidth=150)

        vsb.config(command=self.tree.yview)
        hsb.config(command=self.tree.xview)

        # Grid layout
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Bind events
        self.tree.bind('<Double-1>', self.copy_password)
        self.tree.bind('<Return>', self.copy_password)
        self.tree.bind('<Control-c>', self.copy_password)

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready - Double-click password to copy")
        status_bar = tk.Label(self.root, textvariable=self.status_var,
                              relief=tk.SUNKEN, anchor=tk.W,
                              font=("Arial", 10), bg="#f0f0f0")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Add right-click context menu
        self.setup_context_menu()

        # Refresh the list
        self.refresh_list()

    def setup_context_menu(self):
        """Setup right-click context menu for treeview"""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="📋 Copy Username", command=self.copy_username)
        self.context_menu.add_command(label="🔑 Copy Password", command=lambda: self.copy_password(None))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="✏️ Edit", command=self.edit_password)
        self.context_menu.add_command(label="🗑️ Delete", command=self.delete_password)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="🔗 Open Website", command=self.open_website)

        self.tree.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """Show context menu on right-click"""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def open_website(self):
        """Open the selected website in browser"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            website = item['values'][0]

            # Add http:// if not present
            if not website.startswith(('http://', 'https://')):
                url = 'https://' + website
            else:
                url = website

            try:
                webbrowser.open(url)
                self.status_var.set(f"Opened {website} in browser")
            except:
                messagebox.showerror("Error", "Could not open website")

    def clear_search(self):
        """Clear search field"""
        self.search_var.set("")
        self.refresh_list()

    def load_passwords(self):
        """Load passwords from encrypted file"""
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    encrypted_data = json.load(f)

                self.passwords = {}
                for site, data in encrypted_data.items():
                    try:
                        username = self.cipher.decrypt(data['username'].encode()).decode()
                        password = self.cipher.decrypt(data['password'].encode()).decode()
                        self.passwords[site] = {'username': username, 'password': password}
                    except Exception as e:
                        print(f"Error decrypting {site}: {e}")
                        continue
            except Exception as e:
                print(f"Error loading passwords: {e}")
                self.passwords = {}
        else:
            self.passwords = {}

    def save_passwords(self):
        """Save passwords to encrypted file"""
        encrypted_data = {}
        for site, data in self.passwords.items():
            try:
                username = self.cipher.encrypt(data['username'].encode()).decode()
                password = self.cipher.encrypt(data['password'].encode()).decode()
                encrypted_data[site] = {'username': username, 'password': password}
            except Exception as e:
                print(f"Error encrypting data for {site}: {e}")
                continue

        try:
            with open(self.data_file, 'w') as f:
                json.dump(encrypted_data, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save passwords: {e}")

    def add_password(self):
        """Manually add a password"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Password")
        dialog.geometry("500x350")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        tk.Label(dialog, text="Add New Password",
                 font=("Arial", 14, "bold")).pack(pady=(20, 10))

        # Form frame
        form_frame = tk.Frame(dialog)
        form_frame.pack(pady=10, padx=20)

        # Website
        tk.Label(form_frame, text="Website/Service:",
                 font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=8)
        website_entry = tk.Entry(form_frame, font=("Arial", 11), width=35)
        website_entry.grid(row=0, column=1, padx=10, pady=8)

        # Username/Email
        tk.Label(form_frame, text="Username/Email:",
                 font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=8)
        username_entry = tk.Entry(form_frame, font=("Arial", 11), width=35)
        username_entry.grid(row=1, column=1, padx=10, pady=8)

        # Password
        tk.Label(form_frame, text="Password:",
                 font=("Arial", 11)).grid(row=2, column=0, sticky=tk.W, pady=8)
        password_entry = tk.Entry(form_frame, font=("Arial", 11), width=35, show="*")
        password_entry.grid(row=2, column=1, padx=10, pady=8)

        # Password strength indicator
        strength_label = tk.Label(form_frame, text="Strength: ", font=("Arial", 10))
        strength_label.grid(row=3, column=1, sticky=tk.W, padx=10, pady=5)

        def update_password_strength():
            password = password_entry.get()
            strength = self.get_password_strength(password)

            strength_label.config(text=f"Strength: {strength}")
            if strength == "Weak":
                strength_label.config(fg="red")
            elif strength == "Medium":
                strength_label.config(fg="orange")
            else:
                strength_label.config(fg="green")

        password_entry.bind('<KeyRelease>', lambda e: update_password_strength())

        # Password controls frame
        controls_frame = tk.Frame(form_frame)
        controls_frame.grid(row=2, column=2, padx=5)

        # Show/hide password checkbox
        show_var = tk.BooleanVar()

        def toggle_password():
            password_entry.config(show="" if show_var.get() else "*")

        tk.Checkbutton(controls_frame, text="Show", variable=show_var,
                       command=toggle_password, font=("Arial", 10)).pack(anchor=tk.W)

        # Password generator button
        def generate_password():
            import random
            import string
            length = 16
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            password = ''.join(random.choice(chars) for _ in range(length))
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)
            update_password_strength()

        tk.Button(controls_frame, text="Generate", command=generate_password,
                  font=("Arial", 10), padx=5).pack(pady=5)

        def save():
            website = website_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get().strip()

            if not all([website, username, password]):
                messagebox.showwarning("Warning", "All fields are required!")
                return

            if website in self.passwords:
                if not messagebox.askyesno("Confirm", f"Password for {website} already exists. Overwrite?"):
                    return

            self.passwords[website] = {'username': username, 'password': password}
            self.save_passwords()
            self.refresh_list()
            dialog.destroy()
            self.status_var.set(f"Password saved for {website}")

        def cancel():
            dialog.destroy()

        # Button frame
        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="💾 Save", command=save, font=("Arial", 11),
                  bg="#4CAF50", fg="white", width=12, padx=10).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=cancel, font=("Arial", 11),
                  bg="#f44336", fg="white", width=12, padx=10).pack(side=tk.LEFT, padx=10)

        # Bind Enter key to save
        website_entry.focus_set()
        website_entry.bind('<Return>', lambda e: username_entry.focus_set())
        username_entry.bind('<Return>', lambda e: password_entry.focus_set())
        password_entry.bind('<Return>', lambda e: save())

        dialog.wait_window()

    def edit_password(self):
        """Edit selected password"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to edit!")
            return

        item = self.tree.item(selection[0])
        website = item['values'][0]

        if website not in self.passwords:
            messagebox.showerror("Error", "Selected password not found!")
            return

        current_data = self.passwords[website]

        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Password")
        dialog.geometry("500x350")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        dialog.grab_set()

        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        tk.Label(dialog, text="Edit Password",
                 font=("Arial", 14, "bold")).pack(pady=(20, 10))

        # Form frame
        form_frame = tk.Frame(dialog)
        form_frame.pack(pady=10, padx=20)

        # Website
        tk.Label(form_frame, text="Website/Service:",
                 font=("Arial", 11)).grid(row=0, column=0, sticky=tk.W, pady=8)
        website_entry = tk.Entry(form_frame, font=("Arial", 11), width=35)
        website_entry.insert(0, website)
        website_entry.grid(row=0, column=1, padx=10, pady=8)

        # Username/Email
        tk.Label(form_frame, text="Username/Email:",
                 font=("Arial", 11)).grid(row=1, column=0, sticky=tk.W, pady=8)
        username_entry = tk.Entry(form_frame, font=("Arial", 11), width=35)
        username_entry.insert(0, current_data['username'])
        username_entry.grid(row=1, column=1, padx=10, pady=8)

        # Password
        tk.Label(form_frame, text="Password:",
                 font=("Arial", 11)).grid(row=2, column=0, sticky=tk.W, pady=8)
        password_entry = tk.Entry(form_frame, font=("Arial", 11), width=35, show="*")
        password_entry.insert(0, current_data['password'])
        password_entry.grid(row=2, column=1, padx=10, pady=8)

        # Password strength indicator
        strength_label = tk.Label(form_frame, text="Strength: ", font=("Arial", 10))
        strength_label.grid(row=3, column=1, sticky=tk.W, padx=10, pady=5)

        def update_password_strength():
            password = password_entry.get()
            strength = self.get_password_strength(password)

            strength_label.config(text=f"Strength: {strength}")
            if strength == "Weak":
                strength_label.config(fg="red")
            elif strength == "Medium":
                strength_label.config(fg="orange")
            else:
                strength_label.config(fg="green")

        password_entry.bind('<KeyRelease>', lambda e: update_password_strength())
        update_password_strength()  # Initial update

        # Password controls frame
        controls_frame = tk.Frame(form_frame)
        controls_frame.grid(row=2, column=2, padx=5)

        # Show/hide password checkbox
        show_var = tk.BooleanVar(value=True)

        def toggle_password():
            password_entry.config(show="" if show_var.get() else "*")

        tk.Checkbutton(controls_frame, text="Show", variable=show_var,
                       command=toggle_password, font=("Arial", 10)).pack(anchor=tk.W)

        # Password generator button
        def generate_password():
            import random
            import string
            length = 16
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            password = ''.join(random.choice(chars) for _ in range(length))
            password_entry.delete(0, tk.END)
            password_entry.insert(0, password)
            update_password_strength()

        tk.Button(controls_frame, text="Generate", command=generate_password,
                  font=("Arial", 10), padx=5).pack(pady=5)

        def save():
            new_website = website_entry.get().strip()
            username = username_entry.get().strip()
            password = password_entry.get().strip()

            if not all([new_website, username, password]):
                messagebox.showwarning("Warning", "All fields are required!")
                return

            # If website changed, remove old entry
            if new_website != website:
                del self.passwords[website]

            self.passwords[new_website] = {'username': username, 'password': password}
            self.save_passwords()
            self.refresh_list()
            dialog.destroy()
            self.status_var.set(f"Password updated for {new_website}")

        # Button frame
        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=20)

        tk.Button(btn_frame, text="💾 Save Changes", command=save, font=("Arial", 11),
                  bg="#4CAF50", fg="white", width=15, padx=10).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Cancel", command=dialog.destroy, font=("Arial", 11),
                  bg="#f44336", fg="white", width=15, padx=10).pack(side=tk.LEFT, padx=10)

        # Bind Enter key to save
        website_entry.focus_set()
        website_entry.bind('<Return>', lambda e: username_entry.focus_set())
        username_entry.bind('<Return>', lambda e: password_entry.focus_set())
        password_entry.bind('<Return>', lambda e: save())

        dialog.wait_window()

    def import_from_browser(self):
        """Import passwords from browsers"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Import Passwords from Browser")
        dialog.geometry("700x600")
        dialog.transient(self.root)
        dialog.resizable(True, True)

        # Center dialog
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

        # Instructions frame
        instructions_frame = tk.LabelFrame(dialog, text="⚠️ IMPORTANT: Before importing",
                                           font=("Arial", 11, "bold"))
        instructions_frame.pack(pady=10, padx=10, fill=tk.X)

        tk.Label(instructions_frame,
                 text="• Close ALL browser windows completely\n"
                      "• You may need to run as Administrator\n"
                      "• Some passwords may fail to decrypt\n"
                      "• Consider using CSV export for Chrome 80+",
                 font=("Arial", 10), justify=tk.LEFT, anchor=tk.W).pack(pady=10, padx=20, fill=tk.X)

        tk.Label(dialog, text="Select Browser:", font=("Arial", 12, "bold")).pack(pady=10)

        browser_var = tk.StringVar(value="chrome")

        browsers_frame = tk.Frame(dialog)
        browsers_frame.pack(pady=10)

        browsers = [
            ("Google Chrome", "chrome"),
            ("Microsoft Edge", "edge"),
            ("Import from CSV File", "csv"),
        ]

        for text, value in browsers:
            tk.Radiobutton(browsers_frame, text=text, variable=browser_var,
                           value=value, font=("Arial", 11)).pack(anchor=tk.W, padx=40, pady=5)

        # Progress area
        result_frame = tk.LabelFrame(dialog, text="Import Progress", font=("Arial", 11, "bold"))
        result_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

        result_text = tk.Text(result_frame, height=15, font=("Consolas", 9), wrap=tk.WORD)
        result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        scrollbar = tk.Scrollbar(result_frame, command=result_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        result_text.config(yscrollcommand=scrollbar.set)

        # Progress bar
        progress_var = tk.DoubleVar()
        progress_bar = ttk.Progressbar(dialog, variable=progress_var, maximum=100)
        progress_bar.pack(pady=5, padx=10, fill=tk.X)

        def start_import():
            browser = browser_var.get()
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, f"Starting import from {browser.title()}...\n")
            result_text.insert(tk.END, "=" * 50 + "\n\n")
            dialog.update()

            try:
                passwords = []

                if browser == "csv":
                    # Import from CSV file
                    file_path = filedialog.askopenfilename(
                        title="Select exported passwords CSV file",
                        filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
                    )

                    if file_path:
                        result_text.insert(tk.END, f"Reading CSV file: {file_path}\n")
                        passwords = self.import_from_csv_file(file_path, result_text)
                    else:
                        result_text.insert(tk.END, "No file selected.\n")
                        return

                elif browser == "chrome":
                    if WINDOWS_AVAILABLE:
                        passwords = self.get_chrome_passwords(result_text)
                    else:
                        result_text.insert(tk.END, "Chrome import requires Windows with pywin32.\n")
                        result_text.insert(tk.END, "Please use CSV import method instead.\n")
                        return

                elif browser == "edge":
                    if WINDOWS_AVAILABLE:
                        passwords = self.get_edge_passwords(result_text)
                    else:
                        result_text.insert(tk.END, "Edge import requires Windows with pywin32.\n")
                        result_text.insert(tk.END, "Please use CSV import method instead.\n")
                        return

                if not passwords:
                    result_text.insert(tk.END, "\n✗ No passwords found!\n")
                    return

                total = len(passwords)
                imported = 0
                skipped = 0
                errors = 0

                result_text.insert(tk.END, f"\nProcessing {total} passwords...\n")
                result_text.insert(tk.END, "=" * 50 + "\n")

                for i, (url, username, password) in enumerate(passwords):
                    # Update progress
                    progress = (i + 1) / total * 100
                    progress_var.set(progress)

                    if i % 20 == 0:
                        result_text.insert(tk.END, f"Progress: {i + 1}/{total}\n")
                        dialog.update()

                    if url and username and password:
                        try:
                            # Clean up URL
                            site = url.replace('https://', '').replace('http://', '').split('/')[0].split('?')[0]

                            if not site or len(site) < 3:
                                continue

                            # Check for duplicates
                            if site in self.passwords:
                                # Update if username is different or empty
                                current = self.passwords[site]
                                if current['username'] != username or not current['username']:
                                    self.passwords[site] = {'username': username, 'password': password}
                                    imported += 1
                                    result_text.insert(tk.END, f"✓ Updated: {site}\n")
                                else:
                                    skipped += 1
                            else:
                                self.passwords[site] = {'username': username, 'password': password}
                                imported += 1
                                result_text.insert(tk.END, f"✓ Imported: {site}\n")
                        except Exception as e:
                            errors += 1
                            continue

                # Save and refresh
                self.save_passwords()
                self.refresh_list()

                # Show summary
                result_text.insert(tk.END, f"\n{'=' * 50}\n")
                result_text.insert(tk.END, "✅ IMPORT SUMMARY:\n")
                result_text.insert(tk.END, f"Successfully imported/updated: {imported}\n")
                result_text.insert(tk.END, f"Skipped (duplicates): {skipped}\n")
                result_text.insert(tk.END, f"Errors: {errors}\n")
                result_text.insert(tk.END, f"Total in database: {len(self.passwords)}\n")
                result_text.insert(tk.END, "\n✓ Import completed successfully!\n")

            except Exception as e:
                result_text.insert(tk.END, f"\n✗ Error: {str(e)}\n")
                import traceback
                traceback.print_exc()

        def open_chrome_export():
            """Open Chrome password export page"""
            webbrowser.open('chrome://settings/passwords')
            result_text.insert(tk.END, "Chrome password page opened.\n")
            result_text.insert(tk.END, "Export passwords to CSV, then import here.\n")

        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="🚀 Start Import", command=start_import,
                  font=("Arial", 11), bg="#9C27B0", fg="white", padx=20).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="📖 Open Chrome Export", command=open_chrome_export,
                  font=("Arial", 11), bg="#2196F3", fg="white", padx=20).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Close", command=dialog.destroy,
                  font=("Arial", 11), padx=20).pack(side=tk.LEFT, padx=5)

        dialog.wait_window()

    def get_chrome_passwords(self, result_text):
        """Extract passwords from Chrome"""
        try:
            # Chrome password database path - try multiple possible locations
            possible_paths = [
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default',
                             'Login Data'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data',
                             'Profile 1', 'Login Data'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Default',
                             'Network', 'Cookies'),
            ]

            db_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    db_path = path
                    result_text.insert(tk.END, f"Found database at: {path}\n")
                    break

            if not db_path:
                result_text.insert(tk.END, "✗ Chrome password database not found.\n")
                result_text.insert(tk.END, "Make sure Chrome is installed.\n")
                return []

            # Copy database to temp location
            temp_db = os.path.join(self.data_dir, 'chrome_temp.db')

            # Try multiple times in case of file lock
            for attempt in range(3):
                try:
                    shutil.copy2(db_path, temp_db)
                    result_text.insert(tk.END, f"Database copied (attempt {attempt + 1})\n")
                    break
                except PermissionError:
                    if attempt == 2:
                        result_text.insert(tk.END, "✗ Cannot access Chrome database.\n")
                        result_text.insert(tk.END, "Close ALL Chrome windows completely!\n")
                        return []
                    time.sleep(1)

            # Connect to database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            # Try different table/column names
            try:
                cursor.execute('SELECT action_url, username_value, password_value FROM logins')
            except sqlite3.OperationalError:
                try:
                    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                except sqlite3.OperationalError:
                    conn.close()
                    result_text.insert(tk.END, "✗ Chrome database structure not recognized.\n")
                    return []

            rows = cursor.fetchall()
            result_text.insert(tk.END, f"Found {len(rows)} password entries\n")

            passwords = []
            successful = 0
            failed = 0

            for i, row in enumerate(rows):
                url, username, encrypted_password = row

                # Show progress every 50 entries
                if i % 50 == 0:
                    result_text.insert(tk.END, f"Decrypting {i + 1}/{len(rows)}...\n")
                    result_text.see(tk.END)

                try:
                    if encrypted_password:
                        # Decrypt the password using Windows DPAPI
                        password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]

                        if password:
                            # Try different encodings
                            try:
                                password_str = password.decode('utf-8')
                            except UnicodeDecodeError:
                                try:
                                    password_str = password.decode('latin-1')
                                except:
                                    password_str = str(password)[2:-1]  # Remove b' and '

                            if url and username and password_str:
                                passwords.append((url, username, password_str))
                                successful += 1
                            else:
                                failed += 1
                        else:
                            failed += 1
                    else:
                        failed += 1
                except Exception as e:
                    failed += 1
                    continue

            conn.close()

            # Clean up temp file
            try:
                os.remove(temp_db)
            except:
                pass

            result_text.insert(tk.END, f"\nDecryption results:\n")
            result_text.insert(tk.END, f"Successfully decrypted: {successful}\n")
            result_text.insert(tk.END, f"Failed: {failed}\n")

            if successful == 0:
                result_text.insert(tk.END, "\n⚠️ No passwords could be decrypted!\n")
                result_text.insert(tk.END, "Possible reasons:\n")
                result_text.insert(tk.END, "• Chrome 80+ uses new encryption method\n")
                result_text.insert(tk.END, "• Windows user account protection\n")
                result_text.insert(tk.END, "• Run this program as Administrator\n")
                result_text.insert(tk.END, "\nTry CSV import method instead.\n")

            return passwords

        except Exception as e:
            result_text.insert(tk.END, f"\n✗ Error: {str(e)}\n")
            return []

    def get_edge_passwords(self, result_text):
        """Extract passwords from Edge"""
        try:
            # Edge password database path
            possible_paths = [
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data', 'Default',
                             'Login Data'),
                os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Microsoft', 'Edge', 'User Data',
                             'Profile 1', 'Login Data'),
            ]

            db_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    db_path = path
                    result_text.insert(tk.END, f"Found database at: {path}\n")
                    break

            if not db_path:
                result_text.insert(tk.END, "✗ Edge password database not found.\n")
                return []

            # Copy database
            temp_db = os.path.join(self.data_dir, 'edge_temp.db')

            for attempt in range(3):
                try:
                    shutil.copy2(db_path, temp_db)
                    result_text.insert(tk.END, f"Database copied (attempt {attempt + 1})\n")
                    break
                except PermissionError:
                    if attempt == 2:
                        result_text.insert(tk.END, "✗ Cannot access Edge database.\n")
                        result_text.insert(tk.END, "Close ALL Edge windows completely!\n")
                        return []
                    time.sleep(1)

            # Connect and read
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()

            try:
                cursor.execute('SELECT action_url, username_value, password_value FROM logins')
            except sqlite3.OperationalError:
                try:
                    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                except:
                    conn.close()
                    result_text.insert(tk.END, "✗ Edge database structure not recognized.\n")
                    return []

            rows = cursor.fetchall()
            result_text.insert(tk.END, f"Found {len(rows)} password entries\n")

            passwords = []
            successful = 0

            for i, row in enumerate(rows):
                url, username, encrypted_password = row

                if i % 50 == 0:
                    result_text.insert(tk.END, f"Decrypting {i + 1}/{len(rows)}...\n")
                    result_text.see(tk.END)

                try:
                    if encrypted_password:
                        password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1]
                        if password:
                            try:
                                password_str = password.decode('utf-8')
                            except:
                                try:
                                    password_str = password.decode('latin-1')
                                except:
                                    password_str = str(password)[2:-1]

                            if url and username and password_str:
                                passwords.append((url, username, password_str))
                                successful += 1
                except:
                    continue

            conn.close()

            try:
                os.remove(temp_db)
            except:
                pass

            result_text.insert(tk.END, f"Successfully decrypted: {successful}\n")

            return passwords

        except Exception as e:
            result_text.insert(tk.END, f"\n✗ Edge import error: {str(e)}\n")
            return []

    def import_from_csv_file(self, file_path, result_text):
        """Import passwords from CSV file"""
        passwords = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Try to detect the delimiter
                sample = f.read(1024)
                f.seek(0)

                if ',' in sample:
                    delimiter = ','
                elif ';' in sample:
                    delimiter = ';'
                elif '\t' in sample:
                    delimiter = '\t'
                else:
                    delimiter = ','

                reader = csv.DictReader(f, delimiter=delimiter)

                # Try to find correct column names
                fieldnames = reader.fieldnames or []
                result_text.insert(tk.END, f"CSV columns: {fieldnames}\n")

                # Common column name variations
                url_col = None
                user_col = None
                pass_col = None

                for col in fieldnames:
                    col_lower = col.lower()
                    if 'url' in col_lower or 'website' in col_lower or 'site' in col_lower:
                        url_col = col
                    elif 'user' in col_lower or 'name' in col_lower or 'login' in col_lower:
                        user_col = col
                    elif 'pass' in col_lower:
                        pass_col = col

                if not all([url_col, user_col, pass_col]):
                    # Try to use first 3 columns
                    if len(fieldnames) >= 3:
                        url_col, user_col, pass_col = fieldnames[0], fieldnames[1], fieldnames[2]
                    else:
                        raise Exception("CSV file must have at least 3 columns: URL, Username, Password")

                for row in reader:
                    try:
                        url = row.get(url_col, '').strip()
                        username = row.get(user_col, '').strip()
                        password = row.get(pass_col, '').strip()

                        if url and username and password:
                            passwords.append((url, username, password))
                    except:
                        continue

            result_text.insert(tk.END, f"Found {len(passwords)} passwords in CSV\n")
            return passwords

        except Exception as e:
            raise Exception(f"Failed to read CSV file: {str(e)}")

    def export_csv(self):
        """Export passwords to CSV file"""
        if not self.passwords:
            messagebox.showwarning("Warning", "No passwords to export!")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="passwords_export.csv"
        )

        if file_path:
            try:
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Website', 'Username', 'Password'])

                    for site, data in sorted(self.passwords.items()):
                        writer.writerow([site, data['username'], data['password']])

                self.status_var.set(f"Passwords exported to {os.path.basename(file_path)}")
                messagebox.showinfo("Success", f"Exported {len(self.passwords)} passwords to CSV!")

            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")

    def create_backup(self):
        """Create a backup of the password database"""
        try:
            # Create backup directory if it doesn't exist
            if not os.path.exists(self.backup_dir):
                os.makedirs(self.backup_dir)

            # Create timestamp for backup file
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = os.path.join(self.backup_dir, f"backup_{timestamp}.json")

            # Copy the current data file
            shutil.copy2(self.data_file, backup_file)

            # Also backup the key file
            key_backup = os.path.join(self.backup_dir, f"key_{timestamp}.key")
            shutil.copy2(self.key_file, key_backup)

            self.status_var.set(f"Backup created: backup_{timestamp}.json")
            messagebox.showinfo("Backup",
                                f"Backup created successfully!\n\nBackup files:\n{os.path.basename(backup_file)}\n{os.path.basename(key_backup)}")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to create backup: {str(e)}")

    def delete_password(self):
        """Delete selected password"""
        if not self.tree:
            return

        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to delete!")
            return

        item = self.tree.item(selection[0])
        website = item['values'][0]

        if website not in self.passwords:
            messagebox.showerror("Error", "Selected password not found!")
            return

        if messagebox.askyesno("Confirm Delete", f"Delete password for {website}?\n\nThis action cannot be undone!"):
            del self.passwords[website]
            self.save_passwords()
            self.refresh_list()
            self.status_var.set(f"Deleted password for {website}")

    def copy_password(self, event=None):
        """Copy password to clipboard"""
        if not self.tree:
            return

        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            website = item['values'][0]

            if website in self.passwords:
                password = self.passwords[website]['password']
                try:
                    pyperclip.copy(password)
                    self.status_var.set(f"Password for {website} copied to clipboard (will clear in 30 seconds)")

                    # Clear clipboard after 30 seconds
                    def clear_clipboard():
                        time.sleep(30)
                        try:
                            if pyperclip.paste() == password:
                                pyperclip.copy("")
                                self.root.after(0, lambda: self.status_var.set("Clipboard cleared"))
                        except:
                            pass

                    threading.Thread(target=clear_clipboard, daemon=True).start()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")

    def copy_username(self):
        """Copy username to clipboard"""
        selection = self.tree.selection()
        if selection:
            item = self.tree.item(selection[0])
            website = item['values'][0]

            if website in self.passwords:
                username = self.passwords[website]['username']
                try:
                    pyperclip.copy(username)
                    self.status_var.set(f"Username for {website} copied to clipboard")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to copy to clipboard: {e}")

    def refresh_list(self):
        """Refresh the password list"""
        if not self.tree:
            return

        # Store current selection
        selection = self.tree.selection()
        selected_website = None
        if selection:
            item = self.tree.item(selection[0])
            selected_website = item['values'][0]

        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add items (mask passwords)
        for site, data in sorted(self.passwords.items()):
            masked_password = "•" * 12  # Always show 12 dots for consistency
            self.tree.insert("", tk.END, values=(site, data['username'], masked_password))

        # Restore selection if possible
        if selected_website:
            for child in self.tree.get_children():
                if self.tree.item(child)['values'][0] == selected_website:
                    self.tree.selection_set(child)
                    self.tree.focus(child)
                    break

    def filter_passwords(self, *args):
        """Filter passwords based on search"""
        if not self.tree or not self.search_var:
            return

        search_term = self.search_var.get().lower()

        # Clear tree
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Add filtered items
        for site, data in sorted(self.passwords.items()):
            if (search_term in site.lower() or
                    search_term in data['username'].lower()):
                masked_password = "•" * 12
                self.tree.insert("", tk.END, values=(site, data['username'], masked_password))

    def toggle_monitoring(self):
        """Toggle clipboard monitoring"""
        if not self.clipboard_monitor_active:
            # Start monitoring
            self.clipboard_monitor_active = True
            self.monitor_btn.config(text="🛑 Stop Monitor", bg="#FF9800")
            self.monitor_thread = threading.Thread(target=self.monitor_clipboard, daemon=True)
            self.monitor_thread.start()
            self.status_var.set("Clipboard monitoring started - looking for credentials...")
        else:
            # Stop monitoring
            self.clipboard_monitor_active = False
            self.monitor_btn.config(text="🔍 Start Monitor", bg="#2196F3")
            self.status_var.set("Clipboard monitoring stopped")

    def monitor_clipboard(self):
        """Monitor clipboard for username:password patterns"""
        try:
            self.last_clipboard = pyperclip.paste()
        except:
            self.last_clipboard = ""

        while self.clipboard_monitor_active:
            try:
                clipboard_content = pyperclip.paste()

                if clipboard_content != self.last_clipboard and clipboard_content:
                    self.last_clipboard = clipboard_content

                    # Check for common password patterns
                    patterns = [
                        (':', 1),  # username:password
                        ('\t', 1),  # tab-separated
                        ('|', 1),  # pipe-separated
                    ]

                    for delimiter, expected_parts in patterns:
                        if delimiter in clipboard_content and '\n' not in clipboard_content:
                            parts = clipboard_content.split(delimiter, 1)
                            if len(parts) == expected_parts + 1:
                                username = parts[0].strip()
                                password = parts[1].strip()

                                if username and password and len(password) >= 4:
                                    # Show prompt in main thread
                                    self.root.after(0, lambda u=username, p=password: self.prompt_save(u, p))
                                    break  # Only process first valid pattern

                time.sleep(1)
            except Exception as e:
                time.sleep(5)

    def prompt_save(self, username, password):
        """Prompt user to save detected credentials"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Save Password?")
        dialog.geometry("450x300")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(False, False)

        tk.Label(dialog, text="🔍 Credentials Detected in Clipboard!",
                 font=("Arial", 12, "bold")).pack(pady=15)

        info_frame = tk.Frame(dialog, bg="#f0f0f0", relief=tk.RIDGE, bd=2)
        info_frame.pack(pady=10, padx=20, fill=tk.BOTH)

        tk.Label(info_frame, text=f"Username: {username}",
                 font=("Arial", 11), bg="#f0f0f0").pack(pady=8, padx=10, anchor=tk.W)
        tk.Label(info_frame, text=f"Password: {'•' * min(len(password), 12)}",
                 font=("Arial", 11), bg="#f0f0f0").pack(pady=8, padx=10, anchor=tk.W)

        tk.Label(dialog, text="Website/Service name:", font=("Arial", 11)).pack(pady=10)
        website_entry = tk.Entry(dialog, font=("Arial", 11), width=30)
        website_entry.pack(pady=5)
        website_entry.focus()

        btn_frame = tk.Frame(dialog)
        btn_frame.pack(pady=15)

        def save():
            website = website_entry.get().strip()
            if not website:
                messagebox.showwarning("Warning", "Please enter a website name!")
                website_entry.focus()
                return

            if website in self.passwords:
                if not messagebox.askyesno("Confirm", f"Password for {website} already exists. Overwrite?"):
                    return

            self.passwords[website] = {'username': username, 'password': password}
            self.save_passwords()
            self.refresh_list()
            dialog.destroy()
            self.status_var.set(f"Password saved for {website}!")

        def cancel():
            dialog.destroy()
            self.status_var.set("Password not saved")

        tk.Button(btn_frame, text="💾 Save", command=save, font=("Arial", 11),
                  bg="#4CAF50", fg="white", width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Cancel", command=cancel, font=("Arial", 11),
                  bg="#f44336", fg="white", width=10).pack(side=tk.LEFT, padx=5)

        website_entry.bind('<Return>', lambda e: save())

    def on_closing(self):
        """Handle application closing"""
        if self.clipboard_monitor_active:
            self.clipboard_monitor_active = False
        self.root.destroy()


if __name__ == "__main__":
    # Check for required modules
    try:
        import pyperclip
    except ImportError:
        print("Please install pyperclip: pip install pyperclip")
        sys.exit(1)

    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("Please install cryptography: pip install cryptography")
        sys.exit(1)

    root = tk.Tk()
    app = PasswordManager(root)

    # Set closing handler
    root.protocol("WM_DELETE_WINDOW", app.on_closing)

    # Center window on screen
    root.update_idletasks()
    x = (root.winfo_screenwidth() - root.winfo_width()) // 2
    y = (root.winfo_screenheight() - root.winfo_height()) // 2
    root.geometry(f"+{x}+{y}")

    root.mainloop()