# highbrute

A simple brute forcing script for solving DVWA labs Brute Force - High difficulty
In this case, CSRF tokens double up as brute force protection tokens as well.

Usage: python highbrute.py [-h] (-u USERNAME | -U USERNAMES_FILE) -P PASSWORDS [-b BASE_URL] [-v]

DVWA Bruteforce Script

options:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        Single username for the bruteforce attack
  -U USERNAMES_FILE, --usernames-file USERNAMES_FILE
                        Path to the username wordlist file
  -P PASSWORDS, --passwords PASSWORDS
                        Path to the password wordlist file
  -b BASE_URL, --base-url BASE_URL
                        Base URL for the DVWA instance. Example: http://192.168.0.137/dvwa/
  -v, --verbose         Increase verbosity level to DEBUG
