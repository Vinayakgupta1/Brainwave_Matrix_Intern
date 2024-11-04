import tkinter as tk
from tkinter import messagebox, filedialog, font
from urllib.parse import urlparse
import tldextract
import re
import datetime
import csv

# Helper functions to check phishing indicators
def is_ip_address(domain):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain) is not None

def has_suspicious_keywords(url):
    suspicious_keywords = ["login", "secure", "verify", "account", "update", "confirm", "banking", "free", "offer"]
    return any(keyword in url.lower() for keyword in suspicious_keywords)

def has_many_subdomains(domain):
    subdomain_count = len(tldextract.extract(domain).subdomain.split('.'))
    return subdomain_count > 2

def check_url_length(url):
    return len(url) > 75

# Function to scan a single URL and determine phishing risk
def scan_url():
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL.")
        return

    result = scan_single_url(url)
    display_result(result)

    # Clear the input field
    url_entry.delete(0, tk.END)

# Function to scan a single URL and return a result dictionary
def scan_single_url(url):
    parsed_url = urlparse(url)
    domain = tldextract.extract(url).registered_domain

    # Perform checks
    checks = {
        "IP Address in URL": is_ip_address(parsed_url.netloc),
        "Suspicious Keywords": has_suspicious_keywords(url),
        "Excessive Subdomains": has_many_subdomains(domain),
        "URL Length": check_url_length(url),
    }

    # Determine risk level based on flags
    flag_count = sum(checks.values())
    risk_level = "High" if flag_count >= 2 else "Medium" if flag_count == 1 else "Low"
    
    # Log result
    log_result(url, risk_level)
    
    # Return the scan result details
    return {"url": url, "risk_level": risk_level, "checks": checks}

# Function to log results to a CSV file
def log_result(url, risk_level):
    with open("phishing_log.csv", "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([datetime.datetime.now(), url, risk_level])

# Function to display result in the GUI
def display_result(result):
    result_label.config(text=f"Risk Level: {result['risk_level']}", 
                        fg="red" if result['risk_level'] == "High" else "orange" if result['risk_level'] == "Medium" else "green")
    details_label.config(text="\n".join([f"{check}: {'⚠️ Yes' if value else '✅ No'}" for check, value in result['checks'].items()]))

# Function to scan URLs from an uploaded file
def scan_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv")])
    if not file_path:
        return

    # Open file and scan each line as a URL or IP
    with open(file_path, "r") as file:
        results = []
        for line in file:
            url = line.strip()
            if url:
                result = scan_single_url(url)
                results.append(result)

    # Display summary results
    messagebox.showinfo("File Scan Complete", f"Scanned {len(results)} URLs/IPs from file. Check 'phishing_log.csv' for details.")
    summary_result = f"Total Scanned: {len(results)}"
    result_label.config(text=summary_result)
    details_label.config(text="File scan complete. Results saved to 'phishing_log.csv'.")

# Initialize GUI
root = tk.Tk()
root.title("Phishing Link Scanner")
root.geometry("500x500")
root.configure(bg="#f2f2f2")  # Light gray background

# Fonts
title_font = font.Font(family="Helvetica", size=16, weight="bold")
label_font = font.Font(family="Helvetica", size=12)
result_font = font.Font(family="Helvetica", size=14, weight="bold")

# Title Label
title_label = tk.Label(root, text="Phishing Link Scanner", font=title_font, bg="#4A90E2", fg="white")
title_label.pack(fill=tk.X, pady=10)

# URL Entry Frame
input_frame = tk.Frame(root, bg="#f2f2f2")
input_frame.pack(pady=10)
tk.Label(input_frame, text="Enter URL to Scan:", font=label_font, bg="#f2f2f2").pack(side=tk.LEFT, padx=5)
url_entry = tk.Entry(input_frame, width=40, font=label_font)
url_entry.pack(side=tk.LEFT, padx=5)

# Scan Button
scan_button = tk.Button(root, text="Scan URL", command=scan_url, font=label_font, bg="#4A90E2", fg="white", width=20)
scan_button.pack(pady=10)

# File Upload Button
file_button = tk.Button(root, text="Scan from File", command=scan_file, font=label_font, bg="#4A90E2", fg="white", width=20)
file_button.pack(pady=10)

# Result Display Frame
result_frame = tk.Frame(root, bg="#f2f2f2", relief=tk.SUNKEN, bd=2)
result_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

result_label = tk.Label(result_frame, text="Risk Level: N/A", font=result_font, bg="#f2f2f2")
result_label.pack(pady=10)

details_label = tk.Label(result_frame, text="", font=label_font, justify="left", bg="#f2f2f2")
details_label.pack(pady=10)

# Start GUI main loop
root.mainloop()
