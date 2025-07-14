from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit
import time
import random
from signature import DigitalSignature  # Importa a classe de assinatura

# Configuração do Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'seguranca2025!'
socketio = SocketIO(app, cors_allowed_origins="*")

# Inicializa o sistema de assinatura
signature_system = DigitalSignature()

# --- Gerenciamento de Estado ---
user_states = {}

def get_user_state(sid):
    if sid not in user_states:
        user_states[sid] = {'name': 'Visitante', 'last_interaction': time.time()}
    return user_states[sid]

def update_user_state(sid, key, value):
    state = get_user_state(sid)
    state[key] = value
    state['last_interaction'] = time.time()

# --- Comandos do Bot ---
def handle_help(sid, message_text):
    return "Comandos disponíveis: /ola, /ajuda, /clima, /nome [seu nome], /meunome"

def handle_greeting(sid, message_text):
    user_state = get_user_state(sid)
    name = user_state['name']
    return f"Olá, {name}! Como posso ajudar?"

def handle_set_name(sid, message_text):
    parts = message_text.split(' ', 1)
    if len(parts) > 1:
        new_name = parts[1].strip()
        if new_name:
            update_user_state(sid, 'name', new_name)
            return f"Entendido! Agora te chamo de {new_name}."
    return "Você ainda não me falou seu nome. Use /nome [seu nome] para definir."

def handle_get_name(sid, message_text):  
    user_state = get_user_state(sid)
    name = user_state['name']
    if name == 'Visitante':
        return "Você ainda não me falou seu nome. Use /nome [seu nome] para definir."
    return f"Seu nome é: {name}"

bot_commands = {
    "/ajuda": handle_help,
    "/ola": handle_greeting,
    "/nome": handle_set_name,
    "/meunome": handle_get_name
}

def process_message(sid, message):
    if message.startswith('/'):
        cmd = message.split(' ')[0]
        if cmd in bot_commands:
            return bot_commands[cmd](sid, message)
        return "Comando desconhecido. Digite /ajuda para ajuda."
    return f"Utilize algum comando disponível:\n /ola, /ajuda, /clima, /nome [seu nome], /meunome."

# --- Handlers SocketIO ---
@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    user_state = get_user_state(sid)
    emit('resposta', {
        'sender': 'Bot',
        'content': f'Bem-vindo, {user_state["name"]}! Digite /ajuda para comandos.',
        'signature': 'N/A',
        'salt': 'N/A',
        'isUser': False
    }, room=sid)

@socketio.on('mensagem')
def handle_message(message):
    sid = request.sid
    
    # Assina e envia mensagem do usuário
    user_sig, user_salt = signature_system.pss_sign(message, signature_system.user_private)
    emit('resposta', {
        'sender': 'Você',
        'content': message,
        'signature': user_sig,
        'salt': user_salt,
        'isUser': True
    }, broadcast=True)

    # Processa e responde
    response = process_message(sid, message)
    bot_sig, bot_salt = signature_system.pss_sign(response, signature_system.bot_private)
    
    time.sleep(0.3)  # Atraso simulado
    
    emit('resposta', {
        'sender': 'Bot',
        'content': response,
        'signature': bot_sig,
        'salt': bot_salt,
        'isUser': False
    }, room=sid)

if __name__ == '__main__':
    socketio.run(app, debug=True, use_reloader=False)