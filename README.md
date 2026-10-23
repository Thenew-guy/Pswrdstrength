# Password Strength Checker - Project

This small project implements a password strength checker using entropy and heuristic rules.
Files included:
- password_checker.py  : CLI tool to analyze passwords
- gui_password_checker.py : Simple Tkinter GUI wrapper
- common_passwords.txt : Sample common passwords list used for dictionary checks
- REPORT_TEMPLATE.md   : Report scaffold
- requirements.txt     : Minimal requirements

Run CLI:
    python password_checker.py --password "MyP@ssw0rd!"

Run GUI:
    python gui_password_checker.py

Notes:
- This is an educational tool. For production use, consider more advanced libraries (zxcvbn).
- Crack-time estimates are rough approximations.
