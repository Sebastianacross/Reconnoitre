import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
from scanner import ReconScanner

def run_recon():
    output_box.delete("1.0", tk.END)
    url = url_entry.get().strip()
    export_format = export_format_var.get()

    if not url:
        messagebox.showerror("Input Error", "Please enter a valid URL.")
        return

    selected_tasks = {
        "robots": robots_var.get(),
        "scrape": scrape_var.get(),
        "whois": whois_var.get(),
        "ip": ip_var.get(),
        "subdomains": subdomains_var.get(),
        "directories": directories_var.get(),
        "ssl": ssl_var.get(),
        "sec_headers": sec_headers_var.get(),
        "cms": cms_var.get(),
        "title": title_var.get(),
        "broken": broken_var.get(),
        "indexing": indexing_var.get(),
    }

    def gui_output(msg):
        output_box.insert(tk.END, msg + "\n")
        output_box.see(tk.END)

    def task():
        custom_sub_path = sub_wordlist_entry.get() if use_custom_sub_var.get() else None
        custom_dir_path = dir_wordlist_entry.get() if use_custom_dir_var.get() else None

        scanner = ReconScanner(url, gui_output, custom_sub_path, custom_dir_path)
        scanner.run(selected_tasks)
        scanner.export_results(export_format)

    threading.Thread(target=task, daemon=True).start()

def choose_file(entry_field):
    path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
    if path:
        entry_field.delete(0, tk.END)
        entry_field.insert(0, path)

# Create window
root = tk.Tk()
root.title("Website Recon Tool")
root.geometry("800x800")

# URL entry
tk.Label(root, text="Target URL:").pack(anchor="w", padx=10, pady=(10, 0))
url_entry = tk.Entry(root, width=70)
url_entry.pack(padx=10, pady=(0, 10))

# Feature checkboxes
frame1 = tk.LabelFrame(root, text="Scan Options")
frame1.pack(fill="x", padx=10)

robots_var = tk.BooleanVar(value=True)
scrape_var = tk.BooleanVar(value=True)
whois_var = tk.BooleanVar(value=True)
ip_var = tk.BooleanVar(value=True)
subdomains_var = tk.BooleanVar(value=True)
directories_var = tk.BooleanVar(value=True)
ssl_var = tk.BooleanVar(value=True)
sec_headers_var = tk.BooleanVar(value=True)
cms_var = tk.BooleanVar(value=True)
title_var = tk.BooleanVar(value=True)
broken_var = tk.BooleanVar(value=False)
indexing_var = tk.BooleanVar(value=False)

tk.Checkbutton(frame1, text="robots.txt", variable=robots_var).grid(row=0, column=0, sticky="w")
tk.Checkbutton(frame1, text="Homepage Scrape", variable=scrape_var).grid(row=0, column=1, sticky="w")
tk.Checkbutton(frame1, text="WHOIS", variable=whois_var).grid(row=0, column=2, sticky="w")
tk.Checkbutton(frame1, text="IP Lookup", variable=ip_var).grid(row=0, column=3, sticky="w")
tk.Checkbutton(frame1, text="Subdomain Scan", variable=subdomains_var).grid(row=1, column=0, sticky="w")
tk.Checkbutton(frame1, text="Directory Brute-force", variable=directories_var).grid(row=1, column=1, sticky="w")
tk.Checkbutton(frame1, text="SSL Info", variable=ssl_var).grid(row=1, column=2, sticky="w")
tk.Checkbutton(frame1, text="Security Headers", variable=sec_headers_var).grid(row=1, column=3, sticky="w")
tk.Checkbutton(frame1, text="CMS Detection", variable=cms_var).grid(row=2, column=0, sticky="w")
tk.Checkbutton(frame1, text="Fetch Title", variable=title_var).grid(row=2, column=1, sticky="w")
tk.Checkbutton(frame1, text="Broken Link Scan", variable=broken_var).grid(row=2, column=2, sticky="w")
tk.Checkbutton(frame1, text="Directory Indexing", variable=indexing_var).grid(row=2, column=3, sticky="w")

# Custom Wordlist options
frame2 = tk.LabelFrame(root, text="Custom Wordlists")
frame2.pack(fill="x", padx=10, pady=(5, 10))

use_custom_sub_var = tk.BooleanVar(value=False)
use_custom_dir_var = tk.BooleanVar(value=False)

tk.Checkbutton(frame2, text="Use custom subdomain wordlist", variable=use_custom_sub_var).grid(row=0, column=0, sticky="w")
sub_wordlist_entry = tk.Entry(frame2, width=50)
sub_wordlist_entry.grid(row=0, column=1)
tk.Button(frame2, text="Browse", command=lambda: choose_file(sub_wordlist_entry)).grid(row=0, column=2, padx=5)

tk.Checkbutton(frame2, text="Use custom directory wordlist", variable=use_custom_dir_var).grid(row=1, column=0, sticky="w")
dir_wordlist_entry = tk.Entry(frame2, width=50)
dir_wordlist_entry.grid(row=1, column=1)
tk.Button(frame2, text="Browse", command=lambda: choose_file(dir_wordlist_entry)).grid(row=1, column=2, padx=5)

# Export format
tk.Label(root, text="Export Format:").pack(anchor="w", padx=10, pady=(10, 0))
export_format_var = tk.StringVar(value="json")
ttk.Combobox(root, textvariable=export_format_var, values=["json", "csv"], width=10).pack(padx=10, anchor="w")

# Start button
tk.Button(root, text="Start Recon", command=run_recon).pack(pady=10)

# Output box
tk.Label(root, text="Output:").pack(anchor="w", padx=10)
output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=25)
output_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))

root.mainloop()
