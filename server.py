from flask import Flask, request, jsonify
from flask import render_template
import json
from flask import jsonify
import datetime

app = Flask(__name__)

channels = {'default': [], 'rizz_practice': []}
messages = []

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
    app.run()
