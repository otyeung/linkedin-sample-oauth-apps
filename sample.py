import os
import requests
from flask import Flask, redirect, request, session, url_for, render_template
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from dotenv import dotenv_values
from pathlib import Path
import secrets
import pandas as pd

# Determine the correct .env file path
env_path = Path('.env.local') if Path('.env.local').exists() else Path('.env')
print(f"Loading {env_path} file")

# Load environment variables into a dictionary
env_vars = dotenv_values(dotenv_path=env_path)

# Debug function to print environment variables
def print_env_vars():
    print("Environment variables after loading:")
    for key, value in env_vars.items():
        print(f"{key}: {value}")

print_env_vars()  # Print environment variables after loading

# Flask app setup
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', secrets.token_hex(16))

# LinkedIn OAuth credentials
CLIENT_ID = env_vars.get('CLIENT_ID')
CLIENT_SECRET = env_vars.get('CLIENT_SECRET')
REDIRECT_URI = 'http://127.0.0.1:5000/login/authorized'
API_VERSION = env_vars.get('API_VERSION')
AUTHORIZATION_URL = 'https://www.linkedin.com/oauth/v2/authorization'
TOKEN_URL = 'https://www.linkedin.com/oauth/v2/accessToken'

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id, first_name=None, last_name=None, email=None):
        self.id = user_id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    user_info = session.get('user_info')
    if user_info and user_info['user_id'] == user_id:
        return User(user_info['user_id'], user_info['first_name'], user_info['last_name'], user_info['email'])
    return None

@login_manager.unauthorized_handler
def unauthorized():
    return "Unauthorized!", 403

@app.route('/login')
def login():
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'state': 'UVFNwd5fGXGnQOt',  # Should be random for security reasons
        'scope': 'r_liteprofile,r_emailaddress,rw_ads,r_ads'  # Adjust scope based on your needs
    }
    url = requests.Request('GET', AUTHORIZATION_URL, params=params).prepare().url
    return redirect(url)

@app.route('/logout')
def logout():
    session.pop('access_token', None)
    logout_user()
    return redirect(url_for('index'))

@app.route('/login/authorized')
def authorized():
    error = request.args.get('error', '')
    if error:
        return f"Error received: {error}", 400

    code = request.args.get('code')
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    response = requests.post(TOKEN_URL, data=data)
    response_data = response.json()

    if 'access_token' not in response_data:
        return "Failed to obtain access token.", 400

    session['access_token'] = response_data['access_token']
    session['expires_in'] = response_data['expires_in']
    session['refresh_token'] = response_data['refresh_token']
    session['refresh_token_expires_in'] = response_data['refresh_token_expires_in']
    session['scope'] = response_data['scope']

    # Retrieve user profile data
    headers = {
        'Authorization': f"Bearer {session['access_token']}",
        'cache-control': 'no-cache',
        'X-Restli-Protocol-Version': '2.0.0',
        'LinkedIn-Version': API_VERSION
    }

    response = requests.get('https://api.linkedin.com/v2/me', headers=headers)
    profile_data = response.json()

    response = requests.get('https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))', headers=headers)
    email_data = response.json()

    user_id = profile_data['id']
    first_name = profile_data['localizedFirstName']
    last_name = profile_data['localizedLastName']
    email = email_data['elements'][0]['handle~']['emailAddress']

    print(f"{user_id}, {first_name} {last_name}, Logged in with email: {email}, expires in {session['expires_in']} seconds")

    user = User(user_id, first_name, last_name, email)
    login_user(user)

    session['user_info'] = {
        'user_id': user_id,
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'access_token': session['access_token'],
        'expires_in': session['expires_in'],
        'expires_in_days': session['expires_in'] // 86400,
        'refresh_token': session['refresh_token'],
        'refresh_token_expires_in': session['refresh_token_expires_in'],
        'refresh_token_expires_in_days': session['refresh_token_expires_in'] // 86400,
        'scope': session['scope'],
    }

    return redirect(url_for('user'))

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/user')
@login_required
def user():
    user_info = session.get('user_info')
    if not user_info:
        return "User information not found.", 400

    # Fetch the ads accounts
    access_token = user_info['access_token']
    api_version = API_VERSION
    ads_accounts_df = get_ads_accounts(api_version, access_token)

    if ads_accounts_df is not None:
        ads_accounts_html = ads_accounts_df.to_html(index=False)
    else:
        ads_accounts_html = "Failed to retrieve ads accounts."

    return render_template('user.html', user_info=user_info, ads_accounts_html=ads_accounts_html)


def get_ads_accounts(api_version, access_token):
    url = 'https://api.linkedin.com/rest/adAccounts?q=search&search=(type:(values:List(BUSINESS)),status:(values:List(ACTIVE)))'
    headers = {
        'LinkedIn-Version': api_version,
        'X-Restli-Protocol-Version': '2.0.0',
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        ads_accounts = [
            {"id": account["id"], "name": account["name"]}
            for account in data.get("elements", [])
            if "id" in account and "name" in account
        ]
        df = pd.DataFrame(ads_accounts)
        return df
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return None


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
