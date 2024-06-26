# Standard library imports
import atexit, datetime, json, os, secrets, threading, time, uuid, logging

# Third-party imports
from bs4 import BeautifulSoup
from cssmin import cssmin
from flask import (Flask, jsonify, redirect, render_template, request, session, 
                   url_for, send_file)
from htmlmin import minify
from jsmin import jsmin
from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.patch_stdout import patch_stdout
from prompt_toolkit.shortcuts import print_formatted_text
import requests
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)
app.secret_key = os.environ.get('AUTH_KEY')

if app.secret_key is None:
    print("No secret key found. Please set the AUTH_KEY environment variable.")
    os._exit(1)

# Global variables for the server [messages, channels, users]
dbpath = 'data.json'
defaultprofilepicture = "https://awesnap.dev/default_profile_picture.jpg"
messages = []
channels = {}
readOnlyChannels = []
users = {}
sessions = []
session_timeout = 1800 # 60 * (minutes)
logAccess = False
github_url = "Sigma"
bannedUsernameChars = [" ","@","#"]

# Speed Optimizers -- Unused -- Oopsie!
slowChannelRefresh = "20000"
fastChannelRefresh = "5000"
slowMessageRefresh = "5000"
fastMessageRefresh = "1000"
maxMessages = 50

def save_data():
    global users, messages, channels, readOnlyChannels
    data = {
        'messages': messages,
        'channels': channels,
        'users': users,
        'readOnlyChannels': readOnlyChannels,
    }
    with open(dbpath, 'w') as f:
        json.dump(data, f)
    log(f"Data saved at: {datetime.datetime.now().strftime('%H:%M:%S')}")
    print(f"Data saved at: {datetime.datetime.now().strftime('%H:%M:%S')}")

def load_data():
    global users, messages, channels, readOnlyChannels
    try:
        with open(dbpath, 'r') as f:
            data = json.load(f)
        channels = data.get('channels', {})
        messages = {channel: data['messages'].get(channel, []) for channel in channels}
        users = data.get('users', {})
        readOnlyChannels = data.get('readOnlyChannels', [])
        log(f"Data read at: {datetime.datetime.now().strftime('%H:%M:%S')}")
    except:
        log("Failed to read, returning empty data")
        messages, channels, users = {}, [], {}

def getProfilePicture(username):
    global users
    return users.get(username, {}).get('profileUrl', defaultprofilepicture)

def addMessage(username, channel, message):
    global messages, readOnlyChannels
    warning:str = ""
    if message == '':
        return jsonify({'error': 'Message cannot be empty'})
    elif len(message) > 500:
        return jsonify({'error': 'Message cannot be longer than 500 characters'})
    elif channel not in channels and not message.startswith('/'):
        return jsonify({'error': 'Channel does not exist'})
    elif message.startswith('/'):
        return processCommand(message.removeprefix('/'), username, channel)
    # If channel is read only
    elif channel in readOnlyChannels:
        if (getUserPermissionLevel(username) < 1):
            return jsonify({'error': 'Channel is read only'})
        else:
            warning = "(BYPASSED) Warning: You are posting in a read-only channel."
            pass
    # Initialize an empty list for the channel if it doesn't exist
    if channel not in messages:
        messages[channel] = []
    messages[channel].append({
        'username': username,
        'channel': channel,
        'profileUrl': getProfilePicture(username),
        'message': message,
        'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
        'edited': False,
        'uuid': str(uuid.uuid4())
    })
    log(f"#{channel} - {username}: {message}")
    save_data()
    if warning != "":
        return jsonify({'error': warning})
    return jsonify({'success': 'Message added'})

# Serve ./default_profile_picture.jpg
@app.route('/default_profile_picture.jpg', methods=['GET'])
def default_profile_picture():
    return send_file('default_profile_picture.jpg')

# Serve EmojiPicker.js
@app.route('/EmojiPicker.js', methods=['GET'])
def EmojiPicker():
    return send_file('EmojiPicker.js')

# Serve logo.png
@app.route('/logo.png', methods=['GET'])
def logo():
    return send_file('logo.png')

def getUserPermissionLevel(username):
    global users
    return users.get(username, {}).get('permissionLevel', 0)

def processCommand(command, username, channel):
    global users, messages, channels
    permissionLevel = getUserPermissionLevel(username)

    if username != "System":
        log(f"@{username} is running command: {command}")

    if permissionLevel >= 1:
        if command.startswith('createchannel'):
            tmpchannel = command.removeprefix('createchannel').strip()
            if tmpchannel in channels:
                return {'error': 'Channel already exists'}
            channels.append(tmpchannel)  # Add the new channel to the list
            save_data()  # Save the data after updating the channels list
            return jsonify({'error': 'Channel created'})
        elif command.startswith('deletechannel'):
            tmpchannel = command.removeprefix('deletechannel').strip()
            if tmpchannel not in channels:
                return {'error': 'Channel does not exist'}
            channels.remove(tmpchannel)  # Remove the channel from the list
            messages.pop(tmpchannel, None)  # Delete the messages for the channel
            return jsonify({'error': 'Channel deleted'})
        elif command.startswith('clearchannel'):
            tmpchannel = command.removeprefix('clearchannel').strip()
            if tmpchannel not in channels:
                return {'error': 'Channel does not exist'}
            messages[tmpchannel] = []  # Clear the messages for the channel
            addMessage('System', channel, f"Channel {tmpchannel} cleared")
            return jsonify({'error': 'Channel cleared'})
        elif command.startswith('whereami'):
            return jsonify({'error': f'You are in {channel}'})
        elif command.startswith('log'):
            tmp = command.removeprefix('log').strip()
            log(tmp)
            return jsonify({'error': f'Logged: {tmp}'})
        elif command == "channels":
            return jsonify({'error': ', '.join(channels)})

    if permissionLevel >= 3:
        if command.startswith('adduser'):
            tmp = command.removeprefix('adduser').strip().split(' ')
            user = tmp[0]
            passwd = str(tmp[1])
            if user in users:
                return jsonify({'error': f"{user} already exists"})
            users[user] = {
                'password': generate_password_hash(passwd),
                'permissionLevel': 0,
                'profileUrl': defaultprofilepicture,
                'friends': []
            }
            save_data()
            return jsonify({'error': f'{user} has been created'})
        elif command.startswith('sayin'):
            tmp = command.removeprefix('sayin').strip().split(' ', 1)
            if len(tmp) < 2:
                return {"error": "Both channel and message must be supplied."}
            channel, message = tmp
            if not channel or not message:
                return {"error": "Both channel and message must be supplied."}
            return addMessage(username, channel, message)
        elif command.startswith('messages'):
            channel = command.removeprefix('messages').strip()
            if channel in messages:
                # Get the last 25 messages for the channel
                n_messages = messages[channel][-int(maxMessages):]
                # Format with \n for the print out!
                return jsonify({'error': '\n'.join([msg['message'] for msg in n_messages])})
            else:
                return jsonify({'error': 'Channel does not exist'})

    if permissionLevel >= 4:
        if command.startswith('sudo'):
            tmp = command.removeprefix('sudo').strip().split(' ', 1)
            user = tmp[0]
            message = tmp[-1]
            return addMessage(user, channel, message)
        elif command.startswith('perm'):
            tmp = command.removeprefix('perm').strip().split(' ')
            if len(tmp) < 2:
                return jsonify({'error': 'No permission level specified'})
            user = tmp[0]
            number = int(tmp[1])
            if number >= 5:
                return {'error': 'Permission level cannot be higher than 4'}
            if user in users:
                users[user]['permissionLevel'] = number
                save_data()
                return jsonify({'error': f'Permission level of {user} changed to {number}'})
            else:
                return jsonify({'error': f"{user} doesn't exist"})
        elif command.startswith('deleteuser'):
            user = command.removeprefix('deleteuser').strip()
            if user in users:
                del users[user]
                save_data()
                return jsonify({'error': f'{user} has been deleted'})
            else:
                return jsonify({'error': f"{user} doesn't exist"})
        elif command.startswith('passwd'):
            tmp = command.removeprefix('passwd').strip().split(' ')
            user = tmp[0]
            passwd = str(tmp[1])
            if user in users:
                users[user]['password'] = generate_password_hash(passwd)
                return jsonify({'error': f'Password for {user} has been set.'})
            else:
                return jsonify({'error': f"{user} doesn't exist"})
        elif command.startswith('deauth'):
            tmp = command.removeprefix('deauth').strip()
            if tmp in users:
                success = rmauth(tmp)
                if (success):
                    return jsonify({'error': f'{tmp} has been deauthenticated.'})
                else:
                    return jsonify({'error': f"{tmp} is not authenticated."})
            else:
                return jsonify({'error': f"{tmp} doesn't exist."})
        elif command.startswith('ban'):
            tmp = command.removeprefix('ban').strip()

            # Check if user exists
            if tmp not in users:
                return jsonify({'error': f"{tmp} doesn't exist."})
            
            # Check if user is banned
            if users[tmp].get('banned', False):
                return jsonify({'error': f"{tmp} is already banned."})

            # Can't ban equal or higher permission level
            if getUserPermissionLevel(tmp) >= getUserPermissionLevel(username):
                return jsonify({'error': 'Cannot ban a user with the same or higher permission level.'})

            if tmp in users:
                rmauth(tmp)
                users[tmp]['banned'] = True
                return jsonify({'error': f'{tmp} has been banned.'})
            else:
                return jsonify({'error': f"{tmp} doesn't exist."})
        elif command.startswith('unban'):
            tmp = command.removeprefix('unban').strip()

            # Check if user exists
            if tmp not in users:
                return jsonify({'error': f"{tmp} doesn't exist."})
            
            # Check if user is banned
            if not users[tmp].get('banned', False):
                return jsonify({'error': f"{tmp} is not banned."})

            # Can't unban equal or higher permission level
            if getUserPermissionLevel(tmp) >= getUserPermissionLevel(username):
                return jsonify({'error': 'Cannot unban a user with the same or higher permission level.'})
            if tmp in users:
                users[tmp]['banned'] = False
                return jsonify({'error': f'{tmp} has been unbanned.'})
            else:
                return jsonify({'error': f"{tmp} doesn't exist."})
        elif command.startswith('lock'):
            tmp = command.removeprefix('lock').strip()
            if tmp in channels:
                readOnlyChannels.append(tmp)
                addMessage('System', channel, f"{tmp} is now read only.")
                return jsonify({'error': f'{tmp} is now read only.'})
            else:
                return jsonify({'error': f"{tmp} doesn't exist."})
        elif command.startswith('unlock'):
            tmp = command.removeprefix('unlock').strip()
            if tmp in readOnlyChannels:
                readOnlyChannels.remove(tmp)
                addMessage('System', channel, f"{tmp} is now read-write.")
                return jsonify({'error': f'{tmp} is now read-write.'})
            else:
                return jsonify({'error': f"{tmp} doesn't exist."})
        elif command.startswith('su'):
            tmp = command.removeprefix('su').strip()
            if tmp in users:
                # If the user's permission level isn't higher or equal to the current user's permission level
                if getUserPermissionLevel(tmp) >= getUserPermissionLevel(username):
                    return jsonify({'error': 'Cannot switch to a user with the same or higher permission level.'})
                
                # If tmp has no session
                if not any(sess['username'] == tmp for sess in sessions):
                    session['username'] = tmp
                    session['token'] = secrets.token_urlsafe(16)
                    session['theme'] = users[tmp].get('theme', 'light')
                    # If already logged in destroy old session!
                    for sess in sessions:
                        if sess['username'] == session['username']:
                            rmauth(session['username'])
                    genauth(tmp,session['token'])
                    return jsonify({'error': f'Switched to {tmp}. Refresh for best results!'})
                else:
                    return jsonify({'error': 'Cannot switch user, they are online.'})
            else:
                return jsonify({'error': f"{tmp} doesn't exist."})
        
    if username != "System":
        log(f"@{username} tried to run command: {command}")
    return jsonify({'error': f'Unknown command {command}'})

def getUUIDpm(username1, username2):
    sorted_usernames = sorted([username1, username2])
    uuid_str = ''.join(sorted_usernames)
    uuid_val = uuid.uuid5(uuid.NAMESPACE_DNS, uuid_str)
    return "FPM-%"+str(uuid_val)

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    global users, messages, channels
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == "":
            return render_template('login.html', error="Username cannot be empty")
        elif len(username) > 20:
            return render_template('login.html', error="Invalid username") 
        if password == "":
            return render_template('login.html', error="Password cannot be empty")
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            session['token'] = secrets.token_urlsafe(16)
            session['theme'] = users[username].get('theme', 'light')
            # If already logged in destroy old session!
            for sess in sessions:
                if sess['username'] == session['username']:
                    rmauth(session['username'])
            genauth(username,session['token'])
            return redirect(url_for('v3_index'))
        else:
            return render_template('login.html', error="Invalid username or password")
    elif request.method == 'GET':
        log(f"{request.user_agent}")
        if 'Mobile' in request.user_agent.string or 'Android' in request.user_agent.string or 'iPhone' in request.user_agent.string:
            return render_template('mobile/mobile_app.html')
        else:
            return render_template('login.html')

# Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    global users, messages, channels
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == "":
            return render_template('signup.html', error="Username cannot be empty")
        elif len(username) > 20:
            return render_template('signup.html', error="Invalid username") 
        if password == "":
            return render_template('signup.html', error="Password cannot be empty")
        if username in users:
            return render_template('signup.html', error="Username already exists")
        else:
            log(f"User {username} signed up")
            users[username] = {
                'password': generate_password_hash(password),
                'permissionLevel': 0,
                'profileUrl': defaultprofilepicture,
                'friends': []
            }
            log("User created!")
            session['username'] = username
            session['token'] = secrets.token_urlsafe(16)
            session['theme'] = 'light'
            genauth(username,session['token'])
            return redirect(url_for('v3_index'))
    elif request.method == 'GET':
        log(f"{request.user_agent}")
        if 'Mobile' in request.user_agent.string or 'Android' in request.user_agent.string or 'iPhone' in request.user_agent.string:
            return render_template('mobile/mobile_app.html')
        else:
            return render_template('signup.html')

# Logout
@app.route('/logout', methods=['GET'])
def logout():
    global users, messages, channels
    if session == {}:
        return redirect(url_for('login'))
    
    if session['username'] != None:
        log(f"User {session['username']} logged out")
        for sess in sessions:
            if sess['username'] == session['username']:
                sessions.remove(sess)
        session.pop('username', None)
        session.pop('token', None)
    return redirect(url_for('login'))

# Old ui application
@app.route('/v2ui', methods=['GET'])
def v2_index():
    global users, messages, channels
    if 'username' in session:
        log(f"User {session['username']} accessed the index page")
        return render_template('legacy/old_index.html', token=session['token'], username=session['username'], profileUrl=getProfilePicture(session['username']))
    else:
        log("A user tried to access the index page without logging in")
        return redirect(url_for('login'))
    
# Main application
@app.route('/', methods=['GET'])
def v3_index():
    global users, messages, channels, commands
    if authcheck(session):
        log(f"User {session['username']} accessed the index page")
        if 'Mobile' in request.user_agent.string or 'Android' in request.user_agent.string or 'iPhone' in request.user_agent.string:
            return render_template("mobile/mobile_app.html")
        else:
            return render_template('index.html', token=session['token'], username=session['username'], profileUrl=getProfilePicture(session['username']),
                                   theme=session['theme'],slowChannelRefresh=slowChannelRefresh, fastChannelRefresh=fastChannelRefresh, 
                                   slowMessageRefresh=slowMessageRefresh, fastMessageRefresh=fastMessageRefresh)
    else:
        log("A user tried to access the index page without logging in")
        return redirect(url_for('login'))

# /channels
@app.route('/channels', methods=['GET'])
def getChannels():
    global users, messages, channels
    if request.method == 'GET': 
        local_channels = list(channels)
        # remove channels that start with 'FPM-%'
        local_channels = [channel for channel in channels if not channel.startswith('FPM-')]
        return jsonify({'channels': local_channels, 'friends': getAllMutualFriends(session['username'])})
    
@app.route('/channels/<channel>', methods=['GET', 'POST', 'PATCH', 'DELETE'])
def getMessages(channel):
    global users, messages, channels
    if channel.startswith('@'):
        puser = channel.removeprefix('@')
        channel = getUUIDpm(session['username'], puser)
        if channel not in channels:
            channels.append(channel)
            messages[channel] = []  # Initialize an empty list for the new channel
    if request.method == 'GET':
        if channel in messages:
            n_messages = messages[channel][-int(maxMessages):]  # Get the last 25 messages for the channel
        else:
            n_messages = []  # Return an empty list if the channel does not exist

        for msg in n_messages:
            msg['profileUrl'] = getProfilePicture(msg['username'])
            if msg['username'] == session['username']:
                msg['editable'] = True
                msg['deletable'] = True
            else:
                msg['editable'] = False
                msg['deletable'] = False
            if getUserPermissionLevel(session['username']) >= 1:
                msg['deletable'] = True

        # If the number of messages is less than or equal to 25, add a message at the beginning
        if len(n_messages) == int(maxMessages):
            end_message = {
                'username': 'System',
                'message': 'To reduce load times, this is the end of your visible message history!',
                'timestamp': "",
                'profileUrl': defaultprofilepicture,
                'channel': channel,
                'editable': False,
                'deletable': False
            }
            n_messages.insert(0, end_message)

        return jsonify(n_messages)
    elif request.method == 'POST':
        message = request.json.get('message', '')
        return addMessage(username=session['username'], channel=channel, message=message)
    elif request.method == 'PATCH':
        uuid = request.json.get('uuid', '')
        message = request.json.get('message', '')
        for msg in messages[channel]:  # Iterate over the messages for the channel
            if msg['uuid'] == uuid and msg['username'] == session['username']:
                msg['message'] = message
                msg['edited'] = True
                return jsonify({'success': 'Message edited'})
        return jsonify({'error': 'Message not found'})
    elif request.method == 'DELETE':
        uuid = request.json.get('uuid', '')
        for msg in messages[channel]:  # Iterate over the messages for the channel
            if msg['uuid'] == uuid and (msg['username'] == session['username'] or getUserPermissionLevel(session['username']) >= 1):
                messages[channel].remove(msg)  # Remove the message from the list for the channel
                return jsonify({'success': 'Message deleted'})
        return jsonify({'error': 'Message not found'})
    return jsonify({'error': 'Server error'},500)

def checkFriend(username, friend):
    global users
    return friend in users.get(username, {}).get('friends', [])

def getAllMutualFriends(username):
    global users
    if username not in users:
        return []
    # Build friends data
    real_friends = users[username].get('friends', {})
    # Build the friends list which needs to have the username and profileUrl
    friends = []
    for friend in real_friends:
        # Only append if the user has friended the friend
        if username in users[friend].get('friends', {}):
            friends.append({'username': friend, 'profileUrl': users[friend].get('profileUrl', defaultprofilepicture)})
    return friends

# /users/<username>
@app.route('/users/<username>', methods=['GET', 'PATCH'])
def getUser(username):
    global users, messages, channels
    # Check if user is logged in

    if session == {}:
        return redirect(url_for('login'))
    
    if request.method == 'GET':
        Editable = username==session['username']
        Friends = getAllMutualFriends(username)
        log(Friends)
        # return render_template('profile.html', username=username, profileUrl=getProfilePicture(username),
        #                         permissionLevel=getUserPermissionLevel(username), about=users.get(username, {}).get('about', 'No about'),
        #                         editable=Editable, isFriend=checkFriend(session['username'], username),
        #                         friends=Friends)
        return jsonify(username=username, profileUrl=getProfilePicture(username),
                               permissionLevel=getUserPermissionLevel(username), about=users.get(username, {}).get('about', 'No about'),
                                 editable=Editable, isFriend=checkFriend(session['username'], username),
                                 friends=Friends)
    elif request.method == 'PATCH':
        if username != session['username']:
            isFriend = request.json.get('isFriend', False)
            if isFriend:
                if username not in users.get(session['username'], {}).get('friends', []):
                    users[session['username']]['friends'].append(username)
                    return jsonify({'success': 'Friend added'})
                else:
                    return jsonify({'error': 'Friend already added'})
            else:
                if username in users.get(session['username'], {}).get('friends', []):
                    users[session['username']]['friends'].remove(username)
                    return jsonify({'success': 'Friend removed'})
                else:
                    return jsonify({'error': 'Friend not found'})
        else:
            about = request.json.get('about', '')
            if len(about) > 500:
                return jsonify({'error': 'About cannot be longer than 500 characters'})
            users[username]['about'] = about
            profileUrl = request.json.get('profileUrl', defaultprofilepicture)
            # if validate_url(profileUrl):
            users[username]['profileUrl'] = profileUrl
            # else:
            #     return jsonify({'error': 'Invalid profile picture URL'})
            theme = request.json.get('theme', 'light')  # Get the theme from the request
            users[username]['theme'] = theme  # Save the theme to the user
            session['theme'] = theme
            return jsonify({'success': 'Profile updated'})
    return jsonify({'error': 'Server error'},500)

# /users/<username>/theme
@app.route('/users/<username>/theme', methods=['GET', 'PATCH'])
def getTheme(username):
    global users, messages, channels
    if request.method == 'GET':
        return jsonify({'theme': users.get(username, {}).get('theme', 'light')})
    elif request.method == 'PATCH':
        theme = request.json.get('theme', 'light')
        users[username]['theme'] = theme
        return jsonify({'success': 'Theme updated'})
    return jsonify({'error': 'Server error'},500)

# /unavailable
@app.route('/unavailable', methods=['GET'])
def unavailable():
    return render_template('unavailable.html',message=f"Resource unavailable")

# Serve favicon.ico
@app.route('/favicon.ico', methods=['GET'])
def favicon():
    return send_file('favicon.ico')

@app.before_request
def preprocessing():
    global users, messages, channels
    # Urls without ANY pre-load authentication
    whitelist = ['/login','/signup','/favicon.ico','/default_profile_picture.jpg','/logo.png','/unavailable','/logout']

    if request.path in whitelist:
        return
    
    # Check if url starts with anything in whitelist
    for path in whitelist:
        if request.path.startswith(path):
            return

    if authcheck(session):
        # Find creation time of session
        banned = False
        # Check if 'banned' key exists in the session
        if 'banned' in users[session['username']]:
            banned = users[session['username']]['banned']
        if banned:
            return render_template('unavailable.html',message=f"{session['username']} is banned from accessing this service.")
        if logAccess:
            log(f"User {session['username']} went to {request.path}")
        return
    else:
        log("Not logged in redirecting to login page")
        return redirect(url_for('login'))

def authcheck(session):
    global sessions
    
    # Session does not exist
    if session == {}:
        return False
    
    
    creation = time.time()
    for sess in sessions:
        if sess['username'] == session["username"] and sess['token'] == session["token"]:
            creation = sess['creation']
    # Session is expired (20 seconds) 
    if time.time() - creation > session_timeout:
        rmauth(session['username'])
        return False
    else: # Refresh session
        for sess in sessions:
            if sess['username'] == session["username"] and sess['token'] == session["token"]:
                sess['creation'] = time.time()

    # Session is not valid
    for sess in sessions:
        if sess['username'] == session["username"] and sess['token'] == session["token"]:
            return True
    try:
        log(f"{session['username']} used invalid token {session['token']}")
    except:
        log(f"Unknown user used an invalid token!")
    return False

def rmauth(username):
    for sess in sessions:
        if sess['username'] == username:
            log(f"Deauthing {username}, token: {sess['token']} is now useless")
            sessions.remove(sess)
            return True
    log(f"User {username} not found in sessions")
    return False

def genauth(username,token):
    global sessions
    sessions.append({"username":username,"token":token,"creation":time.time()})
    log(f"User {username} authenticated with {token}")

def validate_url(url):
    try:
        response = requests.head(url)
        return response.status_code == 200
    except requests.ConnectionError:
        return False

def optimize(source:str,output:str):
    try:
    # Build index_v3.html
        with open(f'./templates/{source}', 'r') as f:
            index_v3 = f.read()
            log(f"Read source {source}")

        soup = BeautifulSoup(index_v3, 'html.parser')

        # Minify JavaScript
        for script in soup.find_all('script'):
            if script.string:
                script.string = jsmin(script.string)

        # Minify CSS
        # for style in soup.find_all('style'):
        #     if style.string:
        #         style.string = cssmin(style.string)

        new_index = minify(str(soup), remove_comments=True)
        log(f"Minified {source}")

        with open(f'./templates/{output}', 'w') as f:
            f.write(new_index)
            log(f"Wrote new {output}")
    except:
        log(f"Failed to minify {source}")

def run_server():
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.INFO)

    # Clear server.log
    with open('server.log', 'w'):
        pass

    handler = logging.FileHandler('server.log')
    handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    ))

    log.addHandler(handler)


    app.run(debug=False)

logs = []

def log(message):
    global logs, new_logs
    logs.append(str(message))
    new_logs = True

MAX_LOGS = 20  # Maximum number of log messages to keep

def print_logs():
    global logs, new_logs
    while True:
        if new_logs:
            with patch_stdout():
                os.system('clear')  # Clear the console
                # Only keep the last MAX_LOGS log messages
                logs = logs[-MAX_LOGS:]
                print_formatted_text(FormattedText([('white', '\n'.join(logs))]))
            new_logs = False
        time.sleep(0.1)

def run_console():
    session = PromptSession()
    global logs, new_logs
    while True:
        try:
            with patch_stdout():
                cmd = session.prompt('> ', auto_suggest=AutoSuggestFromHistory())
            if cmd != "exit" and not "":
                with app.app_context():
                    log(f"> {str(cmd)}")
                    response = processCommand(cmd,'System','System')
                    output = "No command response!"
                    if hasattr(response, 'json') and response.json is not None:
                        if 'error' in response.json:
                            output = response.json['error']
                        elif 'success' in response.json:
                            output = response.json['success']
                    log(f"{output}")
            else:
                log(f"<!> Unreasonable to exit like this, use CTRL+C <!>")
        except Exception as e:
            logs = []
            log(f"<!> Console Error! <!> START!")
            log(f"Exception: {e}")
            log(f"<!> Console Error! <!> END!")
            new_logs = True


if __name__ == '__main__':
    optimize("index_v3.html","index.html")
    optimize("signup_v3.html","signup.html")
    optimize("login_v3.html","login.html")
    optimize("unavailable_v3.html","unavailable.html")

    load_data()

    atexit.register(save_data)

    log_thread = threading.Thread(target=print_logs)
    log_thread.start()

    server_thread = threading.Thread(target=run_server)
    server_thread.start()

    # If a "System" user doesn't exist, leave a blank password so that no one can log in as "System"
    if 'System' not in users:
        users['System'] = {
            'password': generate_password_hash(''),
            'permissionLevel': 5,
            'profileUrl': defaultprofilepicture,
            'friends': []
        }
        log(f"System user created -- Likely first run!")
    
    # If no channels exist, create a "Welcome" channel!
    if len(channels) == 0:
        channels.append('Welcome')
        messages['Welcome'] = []

        addMessage('System', 'Welcome', f"Checkout {github_url} to learn how to setup your own chat server!")

    # console_input = NonBlockingConsoleInput()
    # asyncio.run(run_console(console_input))

    

    run_console()
    server_thread.join()