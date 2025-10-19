# FREE FIRE TCP BOT - EMOTE

A sophisticated TCP bot for Free Fire that enables automated emotes, chat interactions, and squad management through direct server communication.

## ⚠️ Disclaimer

This project is for educational and research purposes only. Use at your own risk. The authors are not responsible for any consequences that may arise from the use of this software.

## 🚀 Features

- **Automated Emote System**: Trigger emotes automatically for yourself and squad members
- **Chat Bot Functionality**: Respond to commands and interact with players
- **TCP Connection Management**: Direct server communication with encryption
- **Squad Management**: Join/leave squads, handle invitations
- **Real-time Message Processing**: Process and respond to live game messages
- **Protocol Buffer Support**: Full protobuf integration for Free Fire's communication protocol

## 🛠️ Technical Features

- AES encryption/decryption for secure communication
- Protocol Buffer message serialization/deserialization
- TCP socket management with automatic reconnection
- Asynchronous I/O for high-performance message handling
- User authentication through Garena's OAuth system

## 📋 Requirements

- Python 3.7+
- Free Fire account credentials
- All dependencies listed in `requirements.txt`

## 📦 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/free-fire-tcp-bot-emote.git
cd free-fire-tcp-bot-emote
```

2. **Install dependencies:**
```bash
pip install -r requirements.txt
```

3. **Generate Protocol Buffer files:**
Make sure the `generated_proto/` directory contains the compiled Python protobuf files from the `.proto` definitions in the `proto/` directory.

## 🔧 Configuration

### Step 1: Set Your Credentials

Edit the credentials in `main.py` around line 480-481:

```python
user_credentials = ("YOUR_BOT_ID", "YOUR_PASSWORD")
```

Replace `"YOUR_BOT_ID"` and `"YOUR_PASSWORD"` with your Free Fire account credentials.

### Step 2: Run the Bot

```bash
python main.py
```

## 🎮 Commands

The bot responds to various commands in the game chat:

### Basic Commands
- `/start` - Activate emote functionality and show available commands
- `/join <teamcode>` - Join a squad using the provided code
- `leave` - Leave the current squad

### Special Commands
- `/5` - Accept squad invitations automatically
- `/s` - Quick squad functionality

### Interactive Responses
The bot automatically responds to greetings like "hi", "hello", "fen", "salam" with a friendly message.

🎥 **Watch Demo Video:** [Watch](https://youtu.be/LlrSCil3O9k)
