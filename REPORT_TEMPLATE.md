# Password Strength Checker — Project Report

**Project:** Password Strength Checker  
**Team / Author:** <Your Name>  
**Date:** 2025-11-13

## 1. Abstract
Short summary: we implement an entropy-based password strength checker that combines
Shannon-entropy estimates with heuristic checks (dictionary, sequences, repeats) and
produces human-friendly suggestions and crack-time estimates.

## 2. Introduction
- Importance of password hygiene.
- Threats from brute-force and dictionary attacks.
- Overview of approach: entropy + heuristics + crack-time estimation.

## 3. Mathematical Background
- Shannon entropy approximation: for password of length L and charset size S:
  H ≈ L * log2(S)
- Explanation of charset size estimation.
- Brief note on guessing-space and time-to-crack formula:
  T = 2^H / G  where G is guesses per second.

## 4. Implementation
- Files: password_checker.py, gui_password_checker.py, common_passwords.txt
- Functions implemented: charset_size, shannon_entropy, detect_sequences, detect_repeats, dictionary_check, score_password
- Scoring heuristics (explain weights and thresholds).

## 5. Experiments & Results
- Test on sample passwords (include table).
- Show plots (optional) of score vs length for random passwords.

## 6. Conclusions & Future Work
- Suggest improvements: integrate zxcvbn, use larger dictionaries, add password strength meters, NIST entropy rules.

## 7. How to run
- CLI: python password_checker.py --password "YourPass1!"
- GUI: python gui_password_checker.py
