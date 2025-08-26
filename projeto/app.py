# app.py
import time
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO
from signature import DigitalSignature
from utils import get_user_state, send_signed_message
from bot import process_message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'seguranca2025!'
socketio = SocketIO(app, cors_allowed_origins="*")

# Instância do sistema de assinatura
signature_system = DigitalSignature()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/verify', methods=['POST'])
def verify_signature_route():
    try:
        data = request.get_json()
        message = data.get('message', '')
        signature_b64 = data.get('signature', '')

        # Verifica com a chave pública do bot
        is_valid = signature_system.pss_verify(message, signature_b64, signature_system.bot_public)
        return jsonify({
            'valid': is_valid,
            'message': 'Assinatura válida!' if is_valid else 'Assinatura inválida!'
        })
    except Exception as e:
        app.logger.exception("Erro na verificação da assinatura")
        return jsonify({'valid': False, 'error': str(e), 'message': 'Erro interno na verificação.'}), 400

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    user_state = get_user_state(sid)
    app.logger.info(f'Cliente conectado: SID={sid}, Nome={user_state["name"]}')
    # Mensagem inicial (não assinada)
    socketio.emit('resposta', {
        'sender': 'Bot',
        'content': f'Bem-vindo, {user_state["name"]}! Digite /ajuda para visualizar os comandos disponíveis.',
        'signature': 'N/A',
        'isUser': False
    }, room=sid)

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info(f'Cliente desconectado: SID={request.sid}')

@socketio.on('mensagem')
def handle_message(message_text: str):
    sid = request.sid
    user_state = get_user_state(sid)
    user_name = user_state['name']
    app.logger.info(f"Mensagem recebida de '{user_name}' (SID: {sid}): '{message_text}'")

    # Assina a mensagem do usuário com a chave privada do usuário
    user_signature_b64, _ = signature_system.pss_sign(message_text, signature_system.user_private)

    # Re-emite a mensagem do usuário (assinada) como broadcast
    send_signed_message(sender=user_name, content=message_text,
                        signature_b64=user_signature_b64, is_user=True,
                        socketio=socketio, room=None, broadcast=True)

    # Processa a mensagem com a lógica do bot
    bot_response_text = process_message(sid, message_text)
    app.logger.info(f"Resposta do bot: '{bot_response_text}'")
    time.sleep(0.7)  # simula um tempo de processamento

    # Assina a resposta do bot com a chave privada do bot
    bot_signature_b64, _ = signature_system.pss_sign(bot_response_text, signature_system.bot_private)

    # Envia a resposta do bot apenas para o cliente que enviou
    send_signed_message(sender='Bot', content=bot_response_text,
                        signature_b64=bot_signature_b64, is_user=False,
                        socketio=socketio, room=sid, broadcast=False)

if __name__ == '__main__':
    socketio.run(app, debug=True, use_reloader=False)
