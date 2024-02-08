import os
import json
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
import datetime
import atexit
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get('AUTH_KEY')

if app.secret_key is None:
    print("No secret key found. Please set the AUTH_KEY environment variable.")
    os._exit(1)

messages = []
users = {}
channels = {}

def save_data():
    """
    Saves the messages, users, and channels to JSON files.

    Parameters:
        None

    Returns:
        None
    """
    with open('messages.json', 'w') as file:
        json.dump(messages, file)
    
    with open('users.json', 'w') as file:
        json.dump(users, file)

    with open('channels.json', 'w') as file:
        json.dump(channels, file)

@app.route('/')
def index():
    print("A person has arrived at the landing page.")
    if 'username' in session:
        # Now use render_template for home.thml
        return render_template('home.html', token=session['token'])
        #return 'Logged in as %s' % session['username']
    # Redirct the user to the signup page
    return redirect(url_for('signup'))
    #return 'You are not logged in'

@app.route('/login', methods=['GET', 'POST'])
def login():
    print("A person has arrvied at the login page.")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            session['token'] = secrets.token_hex(16)  # Generate a unique session token
            session['permissionLevel'] = users[username].get('permissionLevel', 0)  # Get the permissionLevel of the user
            
            return redirect(url_for('index'))
        else:
            return 'Invalid username or password'
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    print("A person has arrvied at the signup page.")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            return 'Username already exists'
        
        users[username] = {
            'password': generate_password_hash(password),
            'permissionLevel': 0
        }
        session['username'] = username  # Generate session
        session['token'] = secrets.token_hex(16)  # Generate a unique session token
        session['permissionLevel'] = 0  # Set default permission level
        print(f"Created user {username}")
        print(users)
        save_data()  # Save the updated user data
        return redirect(url_for('index'))
    return render_template('signup.html'), 401

@app.route('/logout')
def logout():
    # remove the username and token from the session if they're there
    session.pop('username', None)
    session.pop('token', None)
    return redirect(url_for('index'))

@app.route('/sendMessage', methods=['POST'])
def sendMessage():
    global users
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
    permissionLevel = session['permissionLevel']
    
    if not message.strip():  # Check if message is empty or contains only whitespace
        return jsonify({'acknowledgment': 'Message cannot be empty'})
    
    if len(message) > 1000:  # Check if message exceeds 1000 characters
        return jsonify({'acknowledgment': 'Message cannot exceed 1000 characters'})
    
    if channelId not in channels:
        return jsonify({'acknowledgment': 'Channel creation denied'})
    
    if message.startswith('/'):  # Check if message is a command
        return processCommand(message, username, channelId, permissionLevel)
    
    timestamp = datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)")
    new_uuid = str(uuid.uuid4())
    #print(new_uuid)
    #channels[channelId].append({'id': new_uuid, 'channelId': channelId, 'username': username, 'message': message, 'timestamp': timestamp, 'edited': False})
    messages.append({'id': new_uuid, 'channelId': channelId, 'username': username, 'message': message, 'timestamp': timestamp, 'edited': False})
    print(f'#{channelId} > {username}: {message} ({timestamp})')
    return jsonify({'acknowledgment': 'Message received'})

@app.route('/editMessage', methods=['POST'])
def editMessage():
    print(request.json)
    message_id = request.json['id']
    new_content = request.json.get('newContent')
    
    # Find the message with the given id
    for message in messages:
        if message.get('id') == message_id:
            # Check that the username matches the current session's username
            if message.get('username') == session.get('username'):
                # Update the message content
                message['message'] = new_content
                message['edited'] = True
                return jsonify({'acknowledgment': 'Message edited successfully'})
    
    return jsonify({'acknowledgment': 'Message editing failed'})

def processCommand(command, username, channelId, permissionLevel):
    """
    Processes the command sent by the user.

    Parameters:
        command (str): The command sent by the user.
        username (str): The username of the user.
        channelId (str): The ID of the channel.
        permissionLevel (int): The permission level of the user.

    Returns:
        A JSON response indicating the result of the command.
    """
    if permissionLevel < 1:
        print(f"User: {username} ran command: {command}")
        print("User: " + username + " does not have permission to execute commands, permissionLevel: " + str(permissionLevel))
        return jsonify({'acknowledgment': 'Insufficient permission level'})

    
    command = command[1:]  # Remove the leading '/'
    command_parts = command.split(' ')
    command_name = command_parts[0].lower()

    if permissionLevel >=1: 
        if command_name == 'createchannel':
            if len(command_parts) != 2:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            new_channel_id = command_parts[1]
            if new_channel_id in channels:
                return jsonify({'acknowledgment': 'Channel already exists'})
            
            channels[new_channel_id] = []
            messages.append({'channelId': channelId, 'username': 'System', 'message': f'Channel "{new_channel_id}" created', 'timestamp': datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)")})
            return jsonify({'acknowledgment': 'Channel created'})
        elif command_name == 'clearchannel':
            if len(command_parts) != 2:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            channel_id = command_parts[1]
            if channel_id not in channels:
                return jsonify({'acknowledgment': 'Channel does not exist'})
            
            channels[channel_id] = []
            messages.append({'channelId': channelId, 'username': 'System', 'message': f'Channel "{channel_id}" cleared', 'timestamp': datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)")})
            return jsonify({'acknowledgment': 'Channel cleared'})
        elif command_name == 'deletechannel':
            if len(command_parts) != 2:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            channel_id = command_parts[1]
            if channel_id not in channels:
                return jsonify({'acknowledgment': 'Channel does not exist'})
            
            del channels[channel_id]
            messages.append({'channelId': channelId, 'username': 'System', 'message': f'Channel "{channel_id}" deleted', 'timestamp': datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)")})
            return jsonify({'acknowledgment': 'Channel deleted'})
        
        elif command_name == 'getusers':
            if len(command_parts) != 1:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            if permissionLevel < 1:
                return jsonify({'acknowledgment': 'Insufficient permission level'})
            
            for user, data in users.items():
                messages.append({'channelId': channelId, 'username': 'System', 'message': f'{user} : {data["permissionLevel"]}', 'timestamp': datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)")})
            return jsonify({'acknowledgment': 'User information printed'})
    
    if permissionLevel >= 4:
        if command_name == 'deleteuser':
            if len(command_parts) != 2:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            user_to_delete = command_parts[1]
            if user_to_delete not in users:
                return jsonify({'acknowledgment': 'User does not exist'})
            
            del users[user_to_delete]
            messages.append({'channelId': channelId, 'username': 'System', 'message': f'User "{user_to_delete}" deleted', 'timestamp': datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)")})
            return jsonify({'acknowledgment': 'User deleted'})
        elif command_name == 'permuser':
            # Split the command to get the target username and the new permission level
            _, target_username, new_permission_level = command.split()

            # Check if the new permission level is valid (up to 3)
            if int(new_permission_level) > 3:
                return jsonify({'acknowledgment': 'Invalid permission level. Permission level can only go up to 3.'})

            # Check if the target user exists
            if target_username not in users:
                return jsonify({'acknowledgment': 'User not found.'})

            # Set the new permission level for the target user
            users[target_username]['permissionLevel'] = int(new_permission_level)
            messages.append({'channelId': channelId, 'username': 'System', 'message': f'Permission level of {target_username} set to {new_permission_level}.', 'timestamp': datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)")})

            return jsonify({'acknowledgment': f'Permission level of {target_username} set to {new_permission_level}.'})
        
    return jsonify({'acknowledgment': 'Invalid command'})


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
    formatted_messages = []
    for message in messages:
        if message['channelId'] == channelId:
            formatted_message = {
                'id': message['id'],
                'message': message['message'],
                'username': message['username'],
                'timestamp': message['timestamp'],
                'edited': message['edited']
            }
            formatted_messages.append(formatted_message)

    return jsonify({'messages': formatted_messages})

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
                channels.setdefault(channelId, []).append(message)
    else:
        messages = []
    if os.path.exists('users.json'):
        with open('users.json', 'r') as file:
            users:dict = json.load(file)
    else:
        users:dict = {}
    # Load channels from file
    if os.path.exists('channels.json'):
        with open('channels.json', 'r') as file:
            channels = json.load(file)
    else:
        channels = {}

    atexit.register(save_data)
    app.run()
