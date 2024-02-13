import os
import json
from flask import Flask, request, jsonify, session, redirect, url_for, render_template
import datetime
import atexit
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import uuid, time
import concurrent.futures

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
        # Get unix time
        timestamp = datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)")
        new_uuid = str(uuid.uuid4())
        users[username] = {
            'password': generate_password_hash(password),
            'permissionLevel': 0,
            'about': 'I am a new user',
            'profileUrl': 'https://i.pinimg.com/550x/18/b9/ff/18b9ffb2a8a791d50213a9d595c4dd52.jpg',
            'lastOnline': time.time(),
            'friends': [],
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

def sendSystemMessage(channelId, content):
    system_message = {
        'id': str(uuid.uuid4()),
        'channelId': channelId,
        'username': 'System',
        'message': content,
        'timestamp': datetime.datetime.now().strftime("%H:%M (%m/%d/%Y)"),
        'edited': False,
    }
    messages.append(system_message)
    return system_message


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

    print(f"User: {username} ran command: {command}")
    
    command = command[1:]  # Remove the leading '/'
    command_parts = command.split(' ')
    command_name = command_parts[0].lower()

    if command_name == 'logout':
        return redirect(url_for('logout'))
        

    if permissionLevel >=1: 
        if command_name == 'createchannel':
            if len(command_parts) != 2:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            new_channel_id = command_parts[1]
            if new_channel_id in channels:
                return jsonify({'acknowledgment': 'Channel already exists'})
            
            channels[new_channel_id] = []
            sendSystemMessage(channelId, f'Channel "{new_channel_id}" created')
            return jsonify({'acknowledgment': 'Channel created'})
        elif command_name == 'clearchannel':
            if len(command_parts) != 2:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            channel_id = command_parts[1]
            if channel_id not in channels:
                return jsonify({'acknowledgment': 'Channel does not exist'})
            
            channels[channel_id] = []
            sendSystemMessage(channelId, f'Channel "{channel_id}" cleared')
            return jsonify({'acknowledgment': 'Channel cleared'})
        elif command_name == 'deletechannel':
            if len(command_parts) != 2:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            channel_id = command_parts[1]
            if channel_id not in channels:
                return jsonify({'acknowledgment': 'Channel does not exist'})
            
            del channels[channel_id]
            sendSystemMessage(channelId, f'Channel "{channel_id}" deleted')
            return jsonify({'acknowledgment': 'Channel deleted'})
        
        elif command_name == 'getusers':
            if len(command_parts) != 1:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            if permissionLevel < 1:
                return jsonify({'acknowledgment': 'Insufficient permission level'})
            
            for user, data in users.items():
                sendSystemMessage(channelId, f'{user} : {data["permissionLevel"]}')
            return jsonify({'acknowledgment': 'User information printed'})

    if permissionLevel >= 4:
        if command_name == 'deleteuser':
            if len(command_parts) != 2:
                return jsonify({'acknowledgment': 'Invalid command format'})
            
            user_to_delete = command_parts[1]
            if user_to_delete not in users:
                return jsonify({'acknowledgment': 'User does not exist'})
            
            del users[user_to_delete]
            sendSystemMessage(channelId, f'User "{user_to_delete}" deleted')
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
            sendSystemMessage(channelId, f'Permission level of {target_username} set to {new_permission_level}.')
            return jsonify({'acknowledgment': f'Permission level of {target_username} set to {new_permission_level}.'})
        elif command_name == 'sudo':
            # Send a system message to the channel
            sendSystemMessage(channelId, command[5:])
            return jsonify({'acknowledgment': f'Message sent.'})
        
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

    users.get(session['username'], {})['lastOnline'] = time.time()

    formatted_messages = []
    for message in messages:
        if message['channelId'] == channelId:
            try:
                formatted_message = {
                    'id': message['id'],
                    'message': message['message'],
                    'username': message['username'],
                    'timestamp': message['timestamp'],
                    'edited': message['edited'],
                }
            except: # Backup placeholder
                formatted_message = {
                    'id': message['id'],
                    'message': message['message'],
                    'username': message['username'],
                    'timestamp': message['timestamp'],
                    'edited': message['edited'],
                }
                message = formatted_message
            formatted_messages.append(formatted_message)
    return jsonify({'messages': formatted_messages})

@app.route('/editUser', methods=['POST'])
def editUser():
    """
    Edits the user's profile information.

    Parameters:
        None

    Returns:
        A JSON response indicating the success or failure of the edit operation.
    """
    about = request.json.get('about')
    username = request.json.get('username')
    if about is not None:
        if session['username'] == username:
            users[session['username']]['about'] = about
            return jsonify({'message': 'User profile edited successfully'})
        else:
            return jsonify({'message': 'You do not have permission to edit this profile'})
    else:
        return jsonify({'message': 'Invalid request'})


@app.route('/users/<username>', methods=['GET', 'POST'])
def users(username):
    """
    Returns all the users in the system.

    Parameters:
        None

    Returns:
        A JSON response containing the list of users in the system.
    """
    if request.method == 'POST':
        updateFriend:bool = request.json.get('updateFriend', None)
        #print(updateFriend)
        if (updateFriend != None):
            if updateFriend:
                #print("Adding..")
                users[session['username']]['friends'].append(username);
                save_data();
            else:
                #print("Removing..")
                if username in users[session['username']]['friends']:
                    #print("Found in friends")
                    users[session['username']]['friends'].remove(username)
                    #print(users[session['username']]['friends'])
                    save_data();
            return jsonify({'message': 'Friend updated'})
    elif request.method == 'GET':
        for user in users:
            if user == username:
                # Build friends data
                real_friends = users[user].get('friends', {})
                # Build the friends list which needs to have the username and profileUrl
                friends = []
                for friend in real_friends:
                    # Only append if the user has friended the friend
                    if username in users[friend].get('friends', {}):
                        friends.append({'username': friend, 'profileUrl': users[friend].get('profileUrl', 'https://i.pinimg.com/550x/18/b9/ff/18b9ffb2a8a791d50213a9d595c4dd52.jpg')})

                # Convert friends to json
                if username == session['username']:
                    return render_template('profile.html', username=username, permissionLevel=users[username].get('permissionLevel', -1), 
                                        profileUrl="https://i.pinimg.com/550x/18/b9/ff/18b9ffb2a8a791d50213a9d595c4dd52.jpg", 
                                        about=users[username].get('about', 'Im a unmigrated profile :('), owner=True, 
                                        lastOnline = users[username].get('lastOnline', time.time()),
                                        friends=friends, isFriend=isFriends(session['username'], username))
                else:
                    return render_template('profile.html', username=username, permissionLevel=users[username].get('permissionLevel', -1), 
                                        profileUrl="https://i.pinimg.com/550x/18/b9/ff/18b9ffb2a8a791d50213a9d595c4dd52.jpg", 
                                        about=users[username].get('about', 'Im a unmigrated profile :('), owner=False, 
                                        lastOnline = users[username].get('lastOnline', time.time()),
                                        friends=friends, isFriend=isFriends(session['username'], username))
    # Doesn't exist
    return render_template('unknown.html', username=username)

# Method called isFriends, accepts 2 usernames and returns a boolean
def isFriends(user1, user2):
    if user1 in users and user2 in users:
        if user2 in users[user1]['friends'] and user1 in users[user2]['friends']:
            return True
    return False

@app.route('/deleteMessage', methods=['POST'])
def deleteMessage():
    """
    Deletes a message from the messages list.

    Parameters:
        None

    Returns:
        A JSON response indicating whether the message has been deleted.
    """
    message_id = request.json['id']
    username = session['username']
    permissionLevel = session['permissionLevel']
    
    for message in messages:
        print(message['id'],message_id)
        if message['id'] == message_id:
            if message['username'] == username or permissionLevel >= 1:
                print(messages)
                messages.remove(message)
                print(messages)
                return jsonify({'acknowledgment': 'Message deleted'})
            else:
                return jsonify({'acknowledgment': 'Insufficient permission level'})
    
    return jsonify({'acknowledgment': 'Message not found'})

@app.route('/whoAmi', methods=['GET'])
def whoAmi():
    """
    Returns the username of the session.

    Parameters:
        None

    Returns:
        A JSON response containing the username of the session.
    """
    if 'username' in session:
        return jsonify({'username': session['username'], 'permissionLevel': session['permissionLevel'], 'profileUrl': users[session['username']].get('profileUrl', 'https://i.pinimg.com/550x/18/b9/ff/18b9ffb2a8a791d50213a9d595c4dd52.jpg')})
    else:
        return jsonify({'username': None})


@app.before_request
def require_auth():
    # List of routes that don't require authentication
    whitelist = ['/', '/logout', '/login', '/signup','/whoAmi', '/users/']

    # If the requested route is in the whitelist, return early
    if request.path in whitelist:
        return
    
    for white in whitelist:
        if request.path.startswith(white):
            return

    # Get the token from the request headers
    token = request.headers.get('Authorization')

    # Check if the token matches the expected token
    if 'username' in session and session['token'] == token:
        users.get(session['username'], {})['lastOnline'] = time.time()
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
        channels = {"default": []}

    atexit.register(save_data)

    print(messages,users,channels)

    def run_app():
        app.run(debug=False)

    if __name__ == '__main__':
        # Create separate threads for app.run() and socketio.run()
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.submit(run_app)
            #executor.submit(run_socketio)