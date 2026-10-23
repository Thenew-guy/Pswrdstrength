#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox
import sys, os
BASE = os.path.dirname(__file__)
sys.path.insert(0, BASE)
from password_checker import score_password

def analyze():
    pw = entry.get()
    if not pw:
        messagebox.showinfo("Info","Please enter a password.")
        return
    res = score_password(pw)
    score_var.set(str(res["score"]))
    ent_var.set(str(res["entropy_bits"]))
    offline_var.set(res["tt_offline"])
    online_var.set(res["tt_online"])
    suggestions_list.delete(0, tk.END)
    for s in res["suggestions"]:
        suggestions_list.insert(tk.END, s)
    if res["dict_flag"]:
        suggestions_list.insert(tk.END, "Warning: matches common password pattern")

root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("520x420")
frm = ttk.Frame(root, padding=10)
frm.pack(fill="both", expand=True)

ttk.Label(frm, text="Password:").grid(column=0,row=0, sticky="w")
entry = ttk.Entry(frm, width=40, show="*")
entry.grid(column=1,row=0, sticky="w")

analyze_btn = ttk.Button(frm, text="Analyze", command=analyze)
analyze_btn.grid(column=2,row=0, padx=5)

ttk.Label(frm, text="Score:").grid(column=0,row=1, sticky="w")
score_var = tk.StringVar(value="")
ttk.Label(frm, textvariable=score_var).grid(column=1,row=1, sticky="w")

ttk.Label(frm, text="Entropy (bits):").grid(column=0,row=2, sticky="w")
ent_var = tk.StringVar(value="")
ttk.Label(frm, textvariable=ent_var).grid(column=1,row=2, sticky="w")

ttk.Label(frm, text="Offline crack est.:").grid(column=0,row=3, sticky="w")
offline_var = tk.StringVar(value="")
ttk.Label(frm, textvariable=offline_var).grid(column=1,row=3, sticky="w")

ttk.Label(frm, text="Online crack est.:").grid(column=0,row=4, sticky="w")
online_var = tk.StringVar(value="")
ttk.Label(frm, textvariable=online_var).grid(column=1,row=4, sticky="w")

ttk.Label(frm, text="Suggestions / Warnings:").grid(column=0,row=5, sticky="nw")
suggestions_list = tk.Listbox(frm, height=8, width=60)
suggestions_list.grid(column=0,row=6, columnspan=3, pady=5)

root.mainloop()
