# utils.py
import time
from typing import Optional
from flask_socketio import emit

# armazenamento simples em memória (compartilhado entre módulos)
user_states: dict = {}

def get_user_state(sid: str) -> dict:
    """Retorna (ou inicializa) o estado do usuário pelo SID."""
    if sid not in user_states:
        user_states[sid] = {'name': 'Visitante', 'last_interaction': time.time()}
    return user_states[sid]

def update_user_state(sid: str, key: str, value) -> None:
    state = get_user_state(sid)
    state[key] = value
    state['last_interaction'] = time.time()

def send_signed_message(sender: str,
                        content: str,
                        signature_b64: str,
                        is_user: bool,
                        socketio,
                        room: Optional[str] = None,
                        broadcast: bool = False) -> None:
    """
    Emite payload já assinado via SocketIO.
    - socketio: a instância SocketIO (passada de app.py)
    - se broadcast=True envia para todos (compatível com diversas versões)
    """
    payload = {
        'sender': sender,
        'content': content,
        'signature': signature_b64,
        'isUser': is_user
    }


    try:
        if broadcast:
            socketio.emit('resposta', payload, broadcast=True)
        elif room:
            socketio.emit('resposta', payload, room=room)
        else:
            socketio.emit('resposta', payload)
    except TypeError:
        if broadcast:
            socketio.emit('resposta', payload)
        elif room:
            socketio.emit('resposta', payload, room=room)
        else:
            socketio.emit('resposta', payload)
