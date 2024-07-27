from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_file
import os, json, uuid, atexit, time, signal, psutil
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO as Sock
from flask_socketio import join_room, leave_room, emit

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/'
app.secret_key = os.environ.get('AUTH_KEY')
sock = Sock(app,cors_allowed_origins="*")

if app.secret_key is None:
    print("No secret key found. Please set the AUTH_KEY environment variable.")
    os._exit(1)

users = {}
channels = {}
sessions = {}
viewing_profiles = {}
user_rooms = {}  # Mapping of usernames to rooms
last_heartbeat = {}  # Mapping of rooms to last heartbeat
PFP_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif']

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in PFP_EXTENSIONS

def save_data():
    with open('users.json', 'w') as f:
        json.dump(users, f)
    with open('channels.json', 'w') as f:
        json.dump(channels, f)

def load_data():
    global users, channels
    try:
        if os.path.exists('users.json'):
            with open('users.json', 'r') as f:
                users = json.load(f)
        else:
            users = {}
    except json.JSONDecodeError:
        print("Error: 'users.json' is malformatted. Using default values.")
        users = {}

    try:
        if os.path.exists('channels.json'):
            with open('channels.json', 'r') as f:
                channels = json.load(f)
        else:
            channels = {}
    except json.JSONDecodeError:
        print("Error: 'channels.json' is malformatted. Using default values.")
        channels = {}

@app.route('/', methods=['GET'])
def index():
    if checksession(session):
        if checkauth(session['username'], session['token']):
            return render_template('v4/app.html',username=session['username'],theme=session['theme'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['token'] = genauth(username)
            session['theme'] = 'dark'
            return redirect(url_for('index'))
        else:
            error_msg = "Bad credentials. Please try again."
            if not user:
                error_msg = "User not found."
            return jsonify(error=error_msg), 401
    return render_template('v4/login.html')

@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        if users.get(username) == None:
            if len(username) > 16 or len(username) < 3 or not username.isalnum():
                return jsonify(error="Username must be between 3 and 16 characters and contain no special characters."), 400
            if len(password) > 32 or len(password) < 6:
                return jsonify(error="Password must be between 6 and 32 characters."), 400
            profile_picture_url = url_for('static', filename='dpfp.png')
            users[username] = {
                'password': generate_password_hash(password),
                'permissionLevel': 1,
                'about': '',
                'status': 'active',
                'profilePicture': profile_picture_url
            }
            session['username'] = username
            session['token'] = genauth(username)
            session['theme'] = 'dark'
            return redirect(url_for('index'))
        else:
            return jsonify(error="Username already exists."), 409
    return render_template('v4/signup.html')

@app.route('/logout', methods=['POST'])
def logout():
    if checksession(session):
        if checkauth(session['username'], session['token']):
            rmauth(session['username'])
            session.clear()
    return redirect(url_for('login'))

@app.route('/api/v4/channels', methods=['GET','POST','PATCH','DELETE'])
def get_channels():
    if request.method == "GET":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                return jsonify(channels)
        return jsonify({"error":"Unauthorized."})
    elif request.method == "POST":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                if hasPerm(session['username'], 3):
                    if request.json['name'] in channels:
                        return jsonify({"error":"Channel already exists."})
                    name = request.json['name']
                    channels[name] = []
                    send_updates({"action":"refresh_channels"})
                    return jsonify({"success":f"Channel {name} created."})
                send_updates({"notif":"You do not have permission to do that!"},session['username'])
                return jsonify({"error":"Insufficient permissions."})
        return jsonify({"error":"Unauthorized."})
    elif request.method == "PATCH":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                if hasPerm(session['username'], 3):
                    if request.json['name'] not in channels:
                        return jsonify({"error":"Channel not found."})
                    if request.json['newname'] in channels:
                        return jsonify({"error":"Channel already exists."})
                    name = request.json['name']
                    newname = request.json['newname']
                    channels[newname] = channels.pop(name)
                    send_updates({"action":"refresh_channels"})
                    return jsonify({"success":f"Channel {name} renamed to {newname}."})
                send_updates({"notif":"You do not have permission to do that!"},session['username'])
                return jsonify({"error":"Insufficient permissions."})
        return jsonify({"error":"Unauthorized."})
    elif request.method == "DELETE":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                if hasPerm(session['username'], 3):
                    name = request.json['name']
                    channels.pop(name)
                    send_updates({"action":"refresh_channels"})
                    return jsonify({"success":f"Channel {name} deleted."})
                send_updates({"notif":"You do not have permission to do that!"},session['username'])
                return jsonify({"error":"Insufficient permissions."})
        return jsonify({"error":"Unauthorized."})

@app.route('/api/v4/messages', methods=['GET','POST','DELETE','PATCH'])
def get_messages():
    if request.method == "GET":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                print(f"{session['username']} requested messages.")
                # Get the channel and number of messages from the request
                channel = request.args.get('channel')
                num_messages = request.args.get('num_messages', default=20, type=int)
                num_messages = min(num_messages, 100)  # Limit to 100 messages

                # If the channel is in channels, return the specified number of messages
                if channel in channels:
                    messages = channels[channel][-num_messages:]  # Get the latest messages

                    # Add profileUrl to each message
                    for message in messages:
                        user = message['user']
                        profileUrl = users[user]['profilePicture']
                        message['profileUrl'] = profileUrl

                    return jsonify(messages)

                # If the channel is not in channels, return an error
                else:
                    return jsonify({"error": "Channel not found."})

        return jsonify({"error":"Unauthorized."})
    elif request.method == "POST":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                if request.json['channel'] not in channels:
                    return jsonify({"error":"Channel not found."})
                channel = request.json['channel']
                message = request.json['message']
                timestamp = datetime.now().strftime("%m/%d/%Y - %I:%M %p")
                channels[channel].append({"user":session['username'],"message":message, "timestamp":timestamp, "reactions": {}})
                print(f"{session['username']} sent a message to {channel}: {message}")
                send_updates({"channel":channel})
                return jsonify({"success":"Message sent."})
        return jsonify({"error":"Unauthorized."})
    elif request.method == "DELETE":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                channel = request.json['channel']
                index = request.json['index']
                if index >= len(channels[channel]):
                    return jsonify({"error":"Message not found."})
                message_owner = channels[channel][index]['user']
                if hasPerm(session['username'], 5) or session['username'] == message_owner:
                    channels[channel].pop(index)
                    send_updates({"channel":channel})
                    return jsonify({"success":"Message deleted."})
                send_updates({"notif":"Stop using the api bozo!"},session['username'])
                return jsonify({"error":"Insufficient permissions."})
        return jsonify({"error":"Unauthorized."})
    elif request.method == "PATCH":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                channel = request.json['channel']
                index = request.json['index']
                message = request.json['message']
                if index >= len(channels[channel]):
                    return jsonify({"error":"Message not found."})
                reactions = channels[channel][index].get('reactions', {})
                timestamp = channels[channel][index].get('timestamp')
                message_owner = channels[channel][index]['user']
                if hasPerm(session['username'], 5) or session['username'] == message_owner:
                    channels[channel][index] = {"user":session['username'],"message":message+" (edited)", "timestamp":timestamp, "reactions": reactions}
                    send_updates({"channel":channel})
                    return jsonify({"success":"Message edited."})
                send_updates({"notif":"Stop using the api bozo!"},session['username'])
                return jsonify({"error":"Insufficient permissions."})
        return jsonify({"error":"Unauthorized."})

@app.route('/api/v4/users/<username>', methods=['GET','PATCH'])
def profiles(username=None):
    if request.method == "GET":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                if username and username in users:
                    return jsonify(users[username]['about'],users[username]['status'],users[username]['profilePicture'])
                else:
                    return jsonify({"error":"User not found."})
        return jsonify({"error":"Unauthorized."})
    elif request.method == "PATCH":
        if checksession(session):
            if checkauth(session['username'], session['token']):
                if session['username'] == username:
                    profile_picture = request.files.get('profile_picture')
                    about = request.form.get('about')
                    if profile_picture and allowed_file(profile_picture.filename):
                        filename = secure_filename(profile_picture.filename)
                        profile_picture.save(os.path.join(app.config['UPLOAD_FOLDER'], session['username'] + '.' + filename.rsplit('.', 1)[1].lower()))
                        users[session['username']]['profilePicture'] = url_for('static', filename='/' + session['username'] + '.' + filename.rsplit('.', 1)[1].lower())
                    if about:
                        users[session['username']]['about'] = about

                    now = datetime.now()
                    for viewer_username, viewer_data in list(viewing_profiles.items()):
                        if (now - viewer_data['last_ping']).total_seconds() > 2:
                            print(f'{viewer_username} is no longer viewing {viewer_data["profile"]}')
                            del viewing_profiles[viewer_username]
                        elif viewer_data['profile'] == session['username']:
                            print(f'Sending update to {viewer_username}')
                            send_updates({"action":"refresh_profile"}, username=viewer_username)

                    return jsonify({"success":"Profile updated."})
                return jsonify({"error":"Unauthorized."})
        return jsonify({"error":"Unauthorized."})

@app.route('/api/v4/session', methods=['GET'])
def session_info():
    if checksession(session):
        if checkauth(session['username'], session['token']):
            return jsonify({"username":session['username'],"token":session['token'],"permissionLevel":users[session['username']]['permissionLevel']})
    return jsonify({"error":"Unauthorized."})

@app.route('/poweroff', methods=['GET'])
def poweroff():
    return render_template('v4/poweroff.html')

@app.route('/static/<filename>')
def static_files(filename):
    filename = secure_filename(filename)
    if os.path.exists(os.path.join('static', filename)):
        return send_file(os.path.join('static', filename))
    return send_file(os.path.join('static', 'dpfp.png'))

def genauth(username):
    auth = uuid.uuid4()
    sessions[username] = auth
    return auth

def checksession(session):
    return 'username' in session and 'token' in session

def checkauth(username, auth):
    return sessions.get(username) == auth

def rmauth(username):
    try:
        sessions.pop(username)
        return True
    except KeyError:
        return False

def hasPerm(username, perm):
    return users[username]['permissionLevel'] >= perm

@sock.on('connect', namespace='/subscriptions')
def handle_connect():
    global user_rooms
    if request.sid not in user_rooms:
        print(f'Client {request.sid} connected')
        join_room(request.sid)

@sock.on('login', namespace='/subscriptions')
def on_login(data):
    username = data.get('username')
    if username is None:
        print("Error: 'username' not provided")
        send_updates({"notif":"Username not provided in websocket connection.\nFunctionality will be limited."},
                     sid=request.sid)
        return
    global user_rooms
    username = data['username']
    token = data['token']
    print(f"Checking auth for {username} with token {token}")
    if not checkauth(username, uuid.UUID(token)):
        send_updates({"redirect":"/login"}, sid=request.sid)
        print(f"Auth failed for {username}")
        return
    user_rooms[username] = request.sid  # Store the room for this user
    print(f'Client {request.sid} logged in as {username}')

@sock.on('viewing_profile', namespace='/subscriptions')
def handle_viewing_profile(data):
    global viewing_profiles
    username = get_username_from_sid(request.sid)
    viewing_profiles[username] = {'profile': data['profile'], 'last_ping': datetime.now()}

@sock.on('status', namespace='/subscriptions')
def handle_status(data):
    global last_heartbeat, users, viewing_profiles
    username = get_username_from_sid(request.sid)
    last_heartbeat[request.sid] = {'username': username, 'time': datetime.now()}
    if username and username not in users:
        users[username] = {}
    if username:
        old_status = users[username].get('status')
        users[username]['status'] = data['status']
        if old_status != data['status']:
            print(f'{username} is now {data["status"]}')
            now = datetime.now()
            for viewer_username, viewer_data in list(viewing_profiles.items()):
                if (now - viewer_data['last_ping']).total_seconds() > 2:
                    del viewing_profiles[viewer_username]
                elif viewer_data['profile'] == session['username']:
                    send_updates({"action":"refresh_profile"}, username=viewer_username)

def check_heartbeats():
    while True:
        global users, last_heartbeat, viewing_profiles
        now = datetime.now()
        for sid, last_heartbeat_info in list(last_heartbeat.items()):
            username = last_heartbeat_info['username']
            last_heartbeat_time = last_heartbeat_info['time']
            time_diff = (now - last_heartbeat_time).total_seconds()
            if time_diff > 2:
                del last_heartbeat[sid]
                if username and username in users:
                    users[username]['status'] = 'offline'
                    # Emit 'refresh_profile' event to all clients viewing the user's profile
                    for viewer_username, viewer_data in list(viewing_profiles.items()):
                        send_updates({"action":"refresh_profile"}, username=viewer_username)
        time.sleep(2)

def set_all_users_offline():
    global users, viewing_profiles
    for username in users:
        if username:
            users[username]['status'] = 'offline'
    print("Marked all users as offline.")

@sock.on('message', namespace='/subscriptions')
def handle_message(data):
    global user_rooms
    print('Received message: ', data)
    emit('message', data, room=request.sid)

@sock.on('disconnect', namespace='/subscriptions')
def handle_disconnect():
    global user_rooms
    print('Client disconnected')
    # Remove the user from the mapping when they disconnect
    user_rooms = {k: v for k, v in user_rooms.items() if v != request.sid}

def get_username_from_sid(sid):
    for username, room in user_rooms.items():
        if room == sid:
            return username
    print("Error: Could not find username for sid", sid)
    return None

def send_updates(data, username=None, sid=None):
    global user_rooms
    serialized_data = json.dumps(data)
    if username:
        room = user_rooms.get(username)
        if room:
            with app.app_context():
                emit('update', serialized_data, room=room, namespace='/subscriptions')
    elif sid:
        with app.app_context():
            emit('update', serialized_data, room=sid, namespace='/subscriptions')
    else:
        with app.app_context():
            emit('update', serialized_data, namespace='/subscriptions', broadcast=True)
    print(f'Sent update: {serialized_data} to {username or "*"}')

def restart_server():
    save_data()
    send_updates({"redirect":"/poweroff"})
    t:int = 3
    # print("Press CTRL+C to stop the server. Otherwise restarting in 3 seconds.")
    while t > 0:
        print(f"Server will stop in {t} seconds.")
        time.sleep(1)
        t -= 1
    os._exit(0)

load_data()
set_all_users_offline()
sock.start_background_task(target=check_heartbeats)
atexit.register(restart_server)