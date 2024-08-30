import tkinter as tk
from tkinter import messagebox, filedialog, colorchooser
from tkinter import ttk
import hashlib
import bcrypt

# Function to hash the password using the selected algorithm
def hash_password():
    password = entry_password.get()
    algorithm = selected_algorithm.get()
    truncate_length = int(entry_truncate_length.get())
    
    if not password:
        messagebox.showerror("Input Error", "Please enter a password")
        return
    
    # Use a combination of numbers, symbols, and characters in hashing
    special_characters = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~"
    mixed_password = password + ''.join(special_characters)
    
    if algorithm == "bcrypt":
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(mixed_password.encode(), salt).decode()
    elif algorithm == "SHA-256":
        hashed_password = hashlib.sha256(mixed_password.encode()).hexdigest()
    elif algorithm == "SHA-1":
        hashed_password = hashlib.sha1(mixed_password.encode()).hexdigest()
    elif algorithm == "MD5":
        hashed_password = hashlib.md5(mixed_password.encode()).hexdigest()
    elif algorithm == "SHA-512":
        hashed_password = hashlib.sha512(mixed_password.encode()).hexdigest()
    elif algorithm == "SHA-384":
        hashed_password = hashlib.sha384(mixed_password.encode()).hexdigest()
    elif algorithm == "SHA-224":
        hashed_password = hashlib.sha224(mixed_password.encode()).hexdigest()
    else:
        messagebox.showerror("Algorithm Error", "Unsupported Algorithm")
        return

    hashed_password = hashed_password[:truncate_length]
    output_label.config(text=f"Algorithm: {algorithm}\nHashed Password: {hashed_password}")

# Function to save the hashed password to a file
def save_to_file():
    hashed_password = output_label.cget("text").replace("Algorithm: ", "").replace("Hashed Password: ", "")
    if not hashed_password:
        messagebox.showerror("Save Error", "No hashed password to save")
        return
    
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(hashed_password)
        messagebox.showinfo("Save Successful", f"Hashed password saved to {file_path}")

# Function to toggle password visibility
def toggle_password():
    if show_password_var.get():
        entry_password.config(show="")
    else:
        entry_password.config(show="*")

# Function to check password strength and update the strength bar
def check_password_strength(event=None):
    password = entry_password.get()
    strength = "Weak"
    strength_color = "#FF0000"  # Red
    strength_percentage = 0

    if len(password) >= 8 and any(c.isupper() for c in password) and any(c.islower() for c in password) and any(c.isdigit() for c in password) and any(c in "!@#$%^&*()" for c in password):
        strength = "Strong"
        strength_color = "#00FF00"  # Green
        strength_percentage = 100
    elif len(password) >= 6:
        strength = "Medium"
        strength_color = "#FFFF00"  # Yellow
        strength_percentage = 60
    else:
        strength_percentage = 30

    strength_label.config(text=f"Password Strength: {strength}")
    update_strength_bar(strength_percentage, strength_color)

# Function to update the strength bar
def update_strength_bar(percentage, color):
    canvas.delete("all")
    canvas.create_rectangle(0, 0, percentage * 3, 10, fill=color, outline="")
    canvas.update()

# Function to open the navigation panel
def open_nav_panel():
    nav_window = tk.Toplevel(window)
    nav_window.title("Customization Options")
    nav_window.geometry("300x300")

    # Add a canvas and scrollbar to the navigation panel
    canvas = tk.Canvas(nav_window)
    canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(nav_window, orient=tk.VERTICAL, command=canvas.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Create a frame inside the canvas
    custom_frame = tk.Frame(canvas)
    canvas.create_window((0, 0), window=custom_frame, anchor="nw")

    # Update scrollbar and canvas frame
    custom_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    # Font Style
    tk.Label(custom_frame, text="Font Style:").pack(pady=5)
    font_styles = ["Arial", "Courier New", "Helvetica", "Times New Roman"]
    font_style_menu = tk.OptionMenu(custom_frame, selected_font_style, *font_styles)
    font_style_menu.pack(pady=5)

    # Font Size
    tk.Label(custom_frame, text="Font Size:").pack(pady=5)
    font_size_menu = tk.OptionMenu(custom_frame, selected_font_size, *[str(i) for i in range(8, 32, 2)])
    font_size_menu.pack(pady=5)

    # Font Color
    tk.Label(custom_frame, text="Font Color:").pack(pady=5)
    tk.Button(custom_frame, text="Choose Font Color", command=choose_font_color).pack(pady=5)

    # Background Color
    tk.Label(custom_frame, text="Background Color:").pack(pady=5)
    tk.Button(custom_frame, text="Choose Background Color", command=choose_bg_color).pack(pady=5)

    # Apply Changes
    tk.Button(custom_frame, text="Apply Changes", command=apply_customizations).pack(pady=10)

# Function to choose font color
def choose_font_color():
    color_code = colorchooser.askcolor(title="Choose Font Color")[1]
    if color_code:
        global font_color
        font_color = color_code
        update_fonts(selected_font_style.get(), selected_font_size.get())

# Function to choose background color
def choose_bg_color():
    color_code = colorchooser.askcolor(title="Choose Background Color")[1]
    if color_code:
        global bg_color
        bg_color = color_code
        update_background_color()

# Function to update background color
def update_background_color():
    window.config(bg=bg_color)
    input_frame.config(bg=bg_color)
    button_frame.config(bg=bg_color)
    strength_label.config(bg=bg_color)
    output_label.config(bg=bg_color)
    canvas.config(bg=bg_color)
    entry_password.config(bg=font_color)
    entry_truncate_length.config(bg=font_color)

# Function to apply customizations
def apply_customizations():
    font_style = selected_font_style.get()
    font_size = selected_font_size.get()
    update_fonts(font_style, font_size)
    update_background_color()

# Function to update font style and size
def update_fonts(style, size):
    font = (style, size)
    for widget in [strength_label, entry_password, entry_truncate_length, output_label]:
        widget.config(font=font)
    for frame in [button_frame, input_frame]:
        for child in frame.winfo_children():
            child.config(font=font)

# Create the main window
window = tk.Tk()
window.title("Password Hashing Tool")
window.geometry("400x500")  # Adjusted size

# Initialize customization variables after creating the main window
selected_font_style = tk.StringVar(value="Arial")
selected_font_size = tk.StringVar(value="10")
font_color = "#000000"
bg_color = "#D3D3D3"  # Default grey background color

# Apply ttk styling for grey background
window.style = ttk.Style()
window.style.configure("TLabel", font=("Arial", 10), background=bg_color, foreground=font_color)
window.style.configure("TButton", font=("Arial", 10), background="#C0C0C0", foreground=font_color)
window.style.configure("TEntry", fieldbackground="#FFFFFF", background="#FFFFFF")
window.style.configure("TCheckbutton", background=bg_color, foreground=font_color)
window.style.configure("TFrame", background=bg_color)

# Create the menu bar
menu_bar = tk.Menu(window)
window.config(menu=menu_bar)

# Add settings menu
settings_menu = tk.Menu(menu_bar, tearoff=0)
settings_menu.add_command(label="Customization", command=open_nav_panel)
menu_bar.add_cascade(label="Settings", menu=settings_menu)

# Create layout with grey background color

# Password entry
input_frame = ttk.Frame(window, padding="5", style="TFrame")
input_frame.pack(fill="x", padx=10, pady=5)

ttk.Label(input_frame, text="Enter Password:").grid(row=0, column=0, pady=5, sticky="w")
entry_password = ttk.Entry(input_frame, show="*", style="TEntry")
entry_password.grid(row=0, column=1, pady=5, sticky="ew")

show_password_var = tk.BooleanVar()
tk.Checkbutton(input_frame, text="Show Password", variable=show_password_var, command=toggle_password, background=bg_color).grid(row=1, column=1, pady=5, sticky="e")

# Password strength
ttk.Label(input_frame, text="Password Strength:").grid(row=2, column=0, pady=5, sticky="w")
strength_label = ttk.Label(input_frame, text="Weak", background=bg_color, foreground="#FF0000")
strength_label.grid(row=2, column=1, pady=5, sticky="ew")

# Thin strength bar
canvas = tk.Canvas(input_frame, width=300, height=10, bg="#FFFFFF")
canvas.grid(row=3, columnspan=2, pady=5, sticky="w")

# Hashing Algorithm
ttk.Label(input_frame, text="Select Hashing Algorithm:").grid(row=4, column=0, pady=5, sticky="w")
selected_algorithm = tk.StringVar(value="bcrypt")
algorithms = ["bcrypt", "SHA-256", "SHA-1", "MD5", "SHA-512", "SHA-384", "SHA-224"]
algorithm_menu = ttk.OptionMenu(input_frame, selected_algorithm, *algorithms)
algorithm_menu.grid(row=4, column=1, pady=5, sticky="ew")

# Truncate length entry
ttk.Label(input_frame, text="Enter Truncate Length (e.g., 16):").grid(row=5, column=0, pady=5, sticky="w")
entry_truncate_length = ttk.Entry(input_frame, style="TEntry")
entry_truncate_length.insert(0, "16")
entry_truncate_length.grid(row=5, column=1, pady=5, sticky="ew")

# Button to hash the password
button_frame = ttk.Frame(window, padding="5", style="TFrame")
button_frame.pack(fill="x", padx=10, pady=5)

ttk.Button(button_frame, text="Hash Password", command=hash_password).pack(pady=5)

# Label to display the hashed password and algorithm
output_label = ttk.Label(button_frame, text="", background=bg_color, foreground=font_color)
output_label.pack(pady=5, fill="x")

# Button to save the hashed password to a file
ttk.Button(button_frame, text="Save Hashed Password", command=save_to_file).pack(pady=5)

# Adjust padding and grid column configuration for better layout
for frame in [input_frame, button_frame]:
    frame.grid_columnconfigure(1, weight=1)

# Bind password entry to strength check
entry_password.bind("<KeyRelease>", check_password_strength)

# Run the application
window.mainloop()
