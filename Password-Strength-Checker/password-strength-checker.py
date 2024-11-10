import re
import random
import tkinter as tk
from tkinter import messagebox, font
from tkinter import ttk

# Password Evaluation Functions
def check_length(password):
    return len(password) >= 12

def has_uppercase(password):
    return bool(re.search(r"[A-Z]", password))

def has_lowercase(password):
    return bool(re.search(r"[a-z]", password))

def has_digit(password):
    return bool(re.search(r"\d", password))

def has_special_character(password):
    return bool(re.search(r"[@$!%*?&]", password))

def is_unique(password):
    common_passwords = ["password", "123456", "123456789", "qwerty", "abc123", "password1"]
    return password.lower() not in common_passwords

def evaluate_password(password):
    score = 0
    feedback = []

    # Length and complexity checks
    if check_length(password):
        score += 1
    else:
        feedback.append("Password should be at least 12 characters.")

    if has_uppercase(password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    if has_lowercase(password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    if has_digit(password):
        score += 1
    else:
        feedback.append("Add numbers.")

    if has_special_character(password):
        score += 1
    else:
        feedback.append("Add special characters (e.g., @, $, %, *).")

    if is_unique(password):
        score += 1
    else:
        feedback.append("Avoid common passwords.")

    # Determine overall strength
    if score <= 2:
        strength = "Very Weak"
    elif score == 3:
        strength = "Weak"
    elif score == 4:
        strength = "Moderate"
    elif score == 5:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return strength, score, feedback

# Generate a random strong password
def generate_password():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@$!%*?&<>/"
    password = ''.join(random.choice(chars) for _ in range(12))
    return password

# GUI for Password Strength Checker with enhancements
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("500x500")
root.configure(bg="#f0f0f0")

# Title Label
title_font = font.Font(family="Helvetica", size=16, weight="bold")
feedback_font = font.Font(family="Helvetica", size=12)
title_label = tk.Label(root, text="Password Strength Checker", font=title_font, bg="#4A90E2", fg="white")
title_label.pack(fill=tk.X, pady=10)

# Password Entry Frame
input_frame = tk.Frame(root, bg="#f0f0f0")
input_frame.pack(pady=10)
tk.Label(input_frame, text="Enter Password:", font=feedback_font, bg="#f0f0f0").pack(side=tk.LEFT, padx=5)
password_entry = tk.Entry(input_frame, show="*", width=30, font=feedback_font)
password_entry.pack(side=tk.LEFT, padx=5)

# Strength and Feedback Display
strength_label = tk.Label(root, text="Strength: N/A", font=feedback_font, bg="#f0f0f0")
strength_label.pack(pady=10)
feedback_label = tk.Label(root, text="", font=feedback_font, bg="#f0f0f0", justify="left")
feedback_label.pack(pady=10)

# Color-Coded Progress Bar for Password Strength
progress = ttk.Progressbar(root, length=200, mode="determinate")
progress.pack(pady=10)

# Check Password Strength Function
def check_password_strength():
    password = password_entry.get()
    if not password:
        messagebox.showwarning("Input Error", "Please enter a password.")
        return
    
    strength, score, feedback = evaluate_password(password)

    # Update strength label and feedback
    strength_label.config(text=f"Strength: {strength}", fg="green" if strength in ["Strong", "Very Strong"] else "red")
    feedback_label.config(text="\n".join(feedback))

    # Update progress bar and color based on strength
    progress["value"] = score * 20  # Scale score to fit 0-100 range
    if score <= 2:
        progress["style"] = "Red.Horizontal.TProgressbar"
    elif score == 3:
        progress["style"] = "Orange.Horizontal.TProgressbar"
    elif score == 4:
        progress["style"] = "Yellow.Horizontal.TProgressbar"
    else:
        progress["style"] = "Green.Horizontal.TProgressbar"

# Style configuration for progress bar colors
style = ttk.Style()
style.theme_use('default')
style.configure("Red.Horizontal.TProgressbar", troughcolor="#f0f0f0", background="red")
style.configure("Orange.Horizontal.TProgressbar", troughcolor="#f0f0f0", background="orange")
style.configure("Yellow.Horizontal.TProgressbar", troughcolor="#f0f0f0", background="yellow")
style.configure("Green.Horizontal.TProgressbar", troughcolor="#f0f0f0", background="green")

# Generate Password and Display in Entry Field
def generate_and_display_password():
    password = generate_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password)
    check_password_strength()  # Automatically check strength of generated password
    # Make the password visible if "Show Password" is checked
    if show_password_var.get():
        password_entry.config(show="")

# Show/Hide Password Toggle
def toggle_password_visibility():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

# Check Strength and Generate Password Buttons
check_button = tk.Button(root, text="Check Strength", command=check_password_strength, font=feedback_font, bg="#4A90E2", fg="white", width=20)
check_button.pack(pady=10)

generate_button = tk.Button(root, text="Generate Strong Password", command=generate_and_display_password, font=feedback_font, bg="#4A90E2", fg="white", width=20)
generate_button.pack(pady=10)

# Show Password Checkbox
show_password_var = tk.BooleanVar()
show_password_checkbox = tk.Checkbutton(root, text="Show Password", font=feedback_font, bg="#f0f0f0", variable=show_password_var, command=toggle_password_visibility)
show_password_checkbox.pack(pady=5)

# Run the GUI
root.mainloop()
