import os
import json
from flask import Flask, request, jsonify, render_template
import datetime
import atexit
app = Flask(__name__)

channels = {'default': [], 'rizz_practice': []}
messages = []

def save_messages():
    """
    Saves the messages to a JSON file.

    Parameters:
        None

    Returns:
        None
    """
    with open('messages.json', 'w') as file:
        json.dump(messages, file)

@app.route('/')
def home():
    return render_template('home.html')

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
    username = request.json['username']
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
    print(messages)
    
    atexit.register(save_messages)
    app.run()
