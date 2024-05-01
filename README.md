# WebChat
Discord knockoff using flask

# Setup Guide
Check out `Setup.md` for instructions!

# User Guide for Commands!

## Available Commands
## ('/' prefix in app, no prefix in console!)

### Permission Level 1

#### createchannel
- **Usage**: `createchannel <channel_name>`
- **Description**: Creates a new channel with the given name. If the channel already exists, an error message is returned.

#### deletechannel
- **Usage**: `deletechannel <channel_name>`
- **Description**: Deletes the channel with the given name. If the channel does not exist, an error message is returned.

#### clearchannel
- **Usage**: `clearchannel <channel_name>`
- **Description**: Clears all messages from the channel with the given name. If the channel does not exist, an error message is returned.

#### whereami
- **Usage**: `whereami`
- **Description**: Returns the name of the current channel.

#### log
- **Usage**: `log <message>`
- **Description**: Logs the given message to the server log.

#### channels
- **Usage**: `channels`
- **Description**: Returns a list of all existing channels.

### Permission Level 3

#### adduser
- **Usage**: `adduser <username> <password>`
- **Description**: Creates a new user with the given username and password. If the user already exists, an error message is returned.

#### sayin
- **Usage**: `sayin <channel_name> <message>`
- **Description**: Sends the given message to the specified channel. If the channel does not exist, an error message is returned.

#### messages
- **Usage**: `messages <channel_name>`
- **Description**: Returns the last 25 messages from the specified channel. If the channel does not exist, an error message is returned.

### Permission Level 4

#### sudo
- **Usage**: `sudo <username> <message>`
- **Description**: Sends a message as the specified user.

#### perm
- **Usage**: `perm <username> <permission_level>`
- **Description**: Sets the permission level of the specified user. If the user does not exist, an error message is returned.

#### deleteuser
- **Usage**: `deleteuser <username>`
- **Description**: Deletes the specified user. If the user does not exist, an error message is returned.

#### passwd
- **Usage**: `passwd <username> <new_password>`
- **Description**: Changes the password of the specified user. If the user does not exist, an error message is returned.

#### deauth
- **Usage**: `deauth <username>`
- **Description**: Deauthenticates the specified user. If the user does not exist, an error message is returned.

#### ban
- **Usage**: `ban <username>`
- **Description**: Bans the specified user. If the user does not exist, an error message is returned.

#### unban
- **Usage**: `unban <username>`
- **Description**: Unbans the specified user. If the user does not exist, an error message is returned.

#### lock
- **Usage**: `lock <channel_name>`
- **Description**: Locks the specified channel, making it read-only. If the channel does not exist, an error message is returned.

#### unlock
- **Usage**: `unlock <channel_name>`
- **Description**: Unlocks the specified channel, making it writable. If the channel does not exist, an error message is returned.

#### su
- **Usage**: `su <username>`
- **Description**: Switches the current user to the specified user. If the user does not exist, an error message is returned.

# Endpoints!

## Endpoint: /default_profile_picture.jpg

**Method**: GET

**Description**: This endpoint serves the `default_profile_picture.jpg` file. When a GET request is made to this endpoint, the server responds by sending the `default_profile_picture.jpg` file. This can be used to display a default profile picture for users who have not set a custom profile picture.

---

## Endpoint: /EmojiPicker.js

**Method**: GET

**Description**: This endpoint serves the `EmojiPicker.js` file. When a GET request is made to this endpoint, the server responds by sending the `EmojiPicker.js` file. This JavaScript file can be used to provide an emoji picker functionality on the client side.

---

## Endpoint: /logo.png

**Method**: GET

**Description**: This endpoint serves the `logo.png` file. When a GET request is made to this endpoint, the server responds by sending the `logo.png` file. This can be used to display the logo of the application on the client side.

## Endpoint: /v2ui

**Method**: GET

**Description**: This endpoint serves the old user interface of the application. If the user is authenticated, it renders the `old_index.html` template and logs the access. If the user is not authenticated, it redirects the user to the login page.

---

## Endpoint: /

**Method**: GET

**Description**: This endpoint serves the main user interface of the application. If the user is authenticated, it renders the `index.html` template and logs the access. If the user is not authenticated, it redirects the user to the login page.

---

## Endpoint: /channels

**Method**: GET

**Description**: This endpoint returns a list of all existing channels and a list of all mutual friends of the current user in JSON format. It filters out channels that start with 'FPM-'.

---

## Endpoint: /channels/<channel>

**Methods**: GET, POST, PATCH, DELETE

**Description**: This endpoint provides various operations on a specific channel.

- GET: Returns the last 25 messages from the specified channel in JSON format. If the channel does not exist, it returns an empty list. It also adds a system message at the beginning if the number of messages is less than or equal to 25.

- POST: Adds a new message to the specified channel. The message is provided in the request body in JSON format.

- PATCH: Edits an existing message in the specified channel. The UUID of the message and the new message content are provided in the request body in JSON format.

- DELETE: Deletes an existing message from the specified channel. The UUID of the message is provided in the request body in JSON format.

## Endpoint: /users/<username>

**Methods**: GET, PATCH

**Description**: This endpoint provides various operations on a specific user.

- GET: Returns the profile information of the specified user in JSON format. This includes the username, profile picture URL, permission level, about text, whether the profile is editable by the current user, whether the user is a friend of the current user, and a list of all mutual friends.

- PATCH: Updates the profile information of the specified user. The new information is provided in the request body in JSON format. If the specified user is not the current user, it can add or remove the user as a friend. If the specified user is the current user, it can update the about text, profile picture URL, and theme.

---

## Endpoint: /users/<username>/theme

**Methods**: GET, PATCH

**Description**: This endpoint provides various operations on the theme of a specific user.

- GET: Returns the theme of the specified user in JSON format.

- PATCH: Updates the theme of the specified user. The new theme is provided in the request body in JSON format.

---

## Endpoint: /unavailable

**Method**: GET

**Description**: This endpoint serves the `unavailable.html` template. This can be used to display a message to the user when a requested resource is unavailable.

---

## Endpoint: /favicon.ico

**Method**: GET

**Description**: This endpoint serves the `favicon.ico` file. This can be used to display a favicon in the browser tab when the user visits the application.

---

## Function: preprocessing

**Description**: This function is executed before each request. It checks if the request path is in the whitelist. If it is, the function returns and the request is processed normally. If the request path is not in the whitelist, it checks if the user is authenticated. If the user is authenticated and not banned, it logs the access and the request is processed normally. If the user is not authenticated, it redirects the user to the login page. If the user is banned, it serves the `unavailable.html` template with a message that the user is banned.

# Setting up the AUTH_KEY environment variable

This guide will help you set up the `AUTH_KEY` environment variable, which is a secret key used by your application to keep user data secure.

## Step 1: Open the Terminal

First, you need to open the terminal. This is where you can enter commands for your computer to execute.

- On Windows, you can search for `cmd` or `Command Prompt` in the Start menu.
- On macOS, you can search for `Terminal` in Spotlight (press `Cmd + Space` to open Spotlight).
- On Linux, you can usually find the Terminal in your applications menu, or you can press `Ctrl + Alt + T`.

## Step 2: Set the Environment Variable

Next, you need to set the `AUTH_KEY` environment variable. The command to do this depends on the shell you're using. 

- If you're using Bash (the default on most Linux distributions and macOS), use this command:

    ```bash
    export AUTH_KEY="your-secret-key"
    ```

- If you're using Command Prompt on Windows, use this command:

    ```cmd
    set AUTH_KEY="your-secret-key"
    ```

Replace "your-secret-key" with a secret key of your choice. This should be a long, random string that's hard to guess.

## Step 3: Run Your Application

Now you can run your application. If you're running it from the terminal, you can use the same terminal window where you set the `AUTH_KEY` environment variable.

If you close the terminal window, or restart your computer, you'll need to set the `AUTH_KEY` environment variable again. To avoid this, you can set the environment variable permanently. The process to do this depends on your operating system and shell. You can find guides on how to do this online.

## Troubleshooting

If you see a message saying "No secret key found. Please set the AUTH_KEY environment variable." when you run your application, this means the `AUTH_KEY` environment variable isn't set. Make sure you followed the steps correctly, and try again.

Remember, keeping your secret key safe is important for the security of your application. Don't share it with anyone, and don't post it online.