import os
import json
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
import datetime
import atexit
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
app = Flask(__name__)

channels = {'default': [], 'rizz_practice': []}
messages = []
users = {}
app.secret_key = os.environ.get('AUTH_KEY')

def save_data():
    """
    Saves the messages and users to JSON files.

    Parameters:
        None

    Returns:
        None
    """
    with open('messages.json', 'w') as file:
        json.dump(messages, file)
    
    with open('users.json', 'w') as file:
        json.dump(users, file)

@app.route('/')
def index():
    if 'username' in session:
        # Now use render_template for home.thml
        return render_template('home.html', token=session['token'])
        #return 'Logged in as %s' % session['username']
    # Redirct the user to the signup page
    return redirect(url_for('signup'))
    #return 'You are not logged in'

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            session['token'] = secrets.token_hex(16)  # Generate a unique session token
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'
    return render_template('login.html')

@app.route('/logout')
def logout():
    # remove the username and token from the session if they're there
    session.pop('username', None)
    session.pop('token', None)
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            return 'Username already exists'
        
        users[username] = generate_password_hash(password)
        session['username'] = username  # Generate session
        session['token'] = secrets.token_hex(16)  # Generate a unique session token
        print(f"Created user {username}")
        print(users)
        return redirect(url_for('index'))
    
    return render_template('signup.html'), 401

@app.route('/sendMessage', methods=['POST'])
def sendMessage():
    """
    Receives a message from the client and stores it in the messages list.

    Parameters:
        None

    Returns:
        A JSON response indicating whether the message has been received or the channel creation request has been denied.
    """
    message = request.json['message']
    username = session['username']
    channelId = request.json['channelId']
    
    if channelId not in channels:
        return jsonify({'acknowledgment': 'Channel creation denied'})
    
    timestamp = datetime.datetime.now().strftime("%m/%d/%Y")
    channels[channelId].append({'username': username, 'message': message, 'timestamp': timestamp})
    messages.append({'channelId': channelId, 'username': username, 'message': message, 'timestamp': timestamp})
    print(f'#{channelId} > {username}: {message} ({timestamp})')
    return jsonify({'acknowledgment': 'Message received'})

@app.route('/getChannels', methods=['GET'])
def getChannels():
    """
    Returns the list of channel IDs that currently exist.

    Parameters:
        None

    Returns:
        A JSON response containing the list of channel IDs.
    """
    channel_list = list(channels)
    print(f"Channels: {channel_list}")
    return jsonify({'channels': channel_list})

@app.route('/messages/<channelId>', methods=['GET'])
def getMessages(channelId):
    """
    Returns all the messages in a channel.

    Parameters:
        channelId (str): The ID of the channel.

    Returns:
        A JSON response containing the list of messages in the channel.
    """
    if channelId not in channels:
        return jsonify({'error': 'Channel not found'})
    
    channel_messages = channels[channelId]
    return jsonify({'messages': channel_messages})

@app.before_request
def require_auth():
    # List of routes that don't require authentication
    whitelist = ['/', '/logout', '/login', '/signup']

    # If the requested route is in the whitelist, return early
    if request.path in whitelist:
        return

    # Get the token from the request headers
    token = request.headers.get('Authorization')

    # Check if the token matches the expected token
    if 'username' in session and session['token'] == token:
        return

    return render_template('unauthorized.html')

    

if __name__ == '__main__':
    # Load messages from file
    if os.path.exists('messages.json'):
        with open('messages.json', 'r') as file:
            messages = json.load(file)
            for message in messages:
                channelId = message['channelId']
                channels[channelId].append(message)
    else:
        messages = []
    if os.path.exists('users.json'):
        with open('users.json', 'r') as file:
            users = json.load(file)
    else:
        users = {}
    print(users)
    
    atexit.register(save_data)
    app.run()
