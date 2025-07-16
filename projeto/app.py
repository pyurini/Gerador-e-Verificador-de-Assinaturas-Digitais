import base64
import hashlib
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import time
import random
from signature import DigitalSignature  

app = Flask(__name__)
app.config['SECRET_KEY'] = 'seguranca2025!' 
socketio = SocketIO(app, cors_allowed_origins="*")

"Inicializa o sistema de assinatura"
signature_system = DigitalSignature()

"Retorna o estado do usuário associado a um Session ID (sid)."
"Se o sid não existir, um estado padrão é criado e retornado."
user_states = {}
def get_user_state(sid):
    if sid not in user_states:
        user_states[sid] = {'name': 'Visitante', 'last_interaction': time.time()}
    return user_states[sid]

"Atualiza o estado do usuário com uma nova propriedade ou valor."
"Também atualiza o timestamp da última interação do usuário."
def update_user_state(sid, key, value):
    state = get_user_state(sid)
    state[key] = value
    state['last_interaction'] = time.time()

#Aqui comoça a lógica do bot.
# As funções abaixo implementam a lógica de resposta do bot para diferentes comandos.
# Cada função recebe o 'sid' (para acessar o estado do usuário) e a 'message_text' completa.
"Lida com o comando /ajuda, listando os comandos disponíveis para o usuário."
def handle_help(sid, message_text):
    return "Comandos disponíveis: /ola, /ajuda, /nome [seu nome], /meunome."

"Esta função lida com o comando /ola, saudando o usuário pelo nome."
"Se o nome não tiver sido definido, usa 'Visitante' como padrão."
def handle_greeting(sid, message_text):
    user_state = get_user_state(sid)
    name = user_state['name']
    greetings = [
        f"Olá, {name}! Como posso ajudar?",
        f"Oi, {name}! É um prazer falar com você.",
        f"E aí, {name}? Tudo bem?"
    ]
    return random.choice(greetings)

"Esta função lida com o comando /nome [seu nome], permitindo ao usuário definir seu nome."
"Ela extrai o nome da mensagem e o armazena no estado do usuário."
def handle_set_name(sid, message_text):
    parts = message_text.split(' ', 1) # Divide a mensagem em no máximo 2 partes sendo a primeira o comando e a segunda o nome
    if len(parts) > 1:
        new_name = parts[1].strip() 
        if new_name:
            update_user_state(sid, 'name', new_name) # Atualiza o estado do usuário
            return f"Entendido! Agora te chamo de {new_name}."
    return "Você ainda não me falou seu nome. Use /nome [seu nome] para definir."

"Esta função lida com o comando /meunome, informando o nome atual do usuário."
"Se o nome não tiver sido definido, informa que o usuário é um Visitante."
def handle_get_name(sid, message_text):  
    user_state = get_user_state(sid)
    name = user_state['name']
    if name == 'Visitante':
        return "Você ainda não me falou seu nome. Use /nome [seu nome] para definir."
    return f"Seu nome é: {name}"

# Mapeia os comandos do bot para suas respectivas funções de manipulação
# Isso permite que a função process_message chame a função correta com base no comando recebido.
bot_commands = {
    "/ajuda": handle_help,
    "/ola": handle_greeting,
    "/nome": handle_set_name,
    "/meunome": handle_get_name
}

"Processa a mensagem do usuário para determinar a resposta do bot."
"Verifica se a mensagem é um comando ou uma mensagem geral."
def process_message(sid, message):
    message_lower = message.lower().strip()
    if message_lower.startswith('/'):
        cmd = message_lower.split(' ')[0]
        if cmd in bot_commands:
            # Chama a função de manipulação de comando mapeada
            return bot_commands[cmd](sid, message)
        return "Comando desconhecido. Digite /ajuda para ajuda."
    
    # Respostas gerais se não for um comando
    if "olá" in message_lower or "oi" in message_lower:
        return handle_greeting(sid, message)
    elif "como você está" in message_lower:
        return "Eu sou um programa de computador, então estou sempre bem! E você?"
    elif "obrigado" in message_lower or "valeu" in message_lower:
        return "De nada! Fico feliz em ajudar."
    else:
        return f"Utilize algum comando disponível:\n /ola, /ajuda, /nome [seu nome], /meunome."

"Rota principal do Flask que renderiza a página HTML do chat."
@app.route('/')
def index():
    return render_template('index.html')

"Eventos do SocketIO para gerenciar conexões e mensagens dos clientes."
"Esses eventos permitem que o servidor receba mensagens dos clientes e envie respostas."
" Envia uma mensagem de boas-vindas do bot ao cliente que acabou de conectar."
@socketio.on('connect')
def handle_connect():
    sid = request.sid
    user_state = get_user_state(sid)
    print(f'Cliente conectado! SID: {sid}, Nome: {user_state["name"]}')
    # Mensagem de boas-vindas do bot mas não assinada, pois é uma mensagem de sistema inicial 
    emit('resposta', {
        'sender': 'Bot',
        'content': f'Bem-vindo, {user_state["name"]}! Digite /ajuda para visualizar os comandos disponíveis.',
        'signature': 'N/A', 
        'isUser': False
    }, room=sid)

"Evento disparado quando um cliente se desconecta do SocketIO."
"Isso pode ser usado para limpar o estado do usuário ou registrar a desconexão."
@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    print(f'Cliente desconectado! SID: {sid}')

"Evento disparado quando o cliente envia uma mensagem."
"Esta função processa a mensagem do usuário, assina a mensagem, re-emite para todos os clientes,"
"processa a resposta do bot, assina a resposta do bot e envia de volta ao cliente original."
@socketio.on('mensagem') 
def handle_message(message_text): 
    sid = request.sid
    user_name = get_user_state(sid)['name'] # Pega o nome do usuário para exibir

    # Para nos termos uma melhor visualização do que está acontecendo imprime a mensagem do usuário recebida no servidor
    print(f"DEBUG (Servidor): Mensagem recebida de '{user_name}' (SID: {sid}): '{message_text}'")

    # 1. Assina a mensagem do usuário (usando a chave privada do usuário)
    # A função pss_sign agora retorna apenas a assinatura (salt é interno)
    user_signature_b64, _ = signature_system.pss_sign(message_text, signature_system.user_private)
    
    # 2. Re-emite a mensagem do usuário (assinada) para TODOS os clientes
    # Isso garante que a mensagem do usuário apareça para todos no chat.
    emit('resposta', {
        'sender': user_name, 
        'content': message_text,
        'signature': user_signature_b64,
        'isUser': True
    }, broadcast=True)

    # 3. Processa a mensagem com a lógica do bot para obter a resposta
    bot_response_text = process_message(sid, message_text)

    # Imprime a resposta do bot antes de ser enviada 
    print(f"DEBUG (Servidor): Resposta do bot (antes de emitir): '{bot_response_text}'")

    time.sleep(0.7) #tempo de espera para simular processamento do bot

    # 4. Assina a resposta do bot (usando a chave privada do bot)
    bot_signature_b64, _ = signature_system.pss_sign(bot_response_text, signature_system.bot_private)
    
    # 5. Envia a resposta do bot (assinada) APENAS para o cliente que enviou a mensagem original
    # Isso garante que a resposta do bot apareça apenas para o usuário que enviou a mensagem.
    emit('resposta', {
        'sender': 'Bot',
        'content': bot_response_text,
        'signature': bot_signature_b64,
        'isUser': False
    }, room=sid)

"Rota HTTP para verificar assinaturas digitais."
"Esta rota recebe uma mensagem e uma assinatura, e verifica se a assinatura é válida."
@app.route('/verify', methods=['POST'])
def verify_signature_route(): 
    try:
        data = request.get_json()
        message = data['message']
        signature_b64 = data['signature']
        
        # para este exemplo, vamos verificar com a chave pública do bot,
        # já que o botão de verificação está nas mensagens do bot.
        is_valid = signature_system.pss_verify(
            message, 
            signature_b64, 
            signature_system.bot_public # Usamos a chave pública do bot para verificar a assinatura do bot
        )
        
        return jsonify({
            'valid': is_valid,
            'message': 'Assinatura válida!' if is_valid else 'Assinatura inválida!'
        })
    except Exception as e:
        print(f"Erro na verificação da assinatura: {e}") # Loga o erro no servidor
        return jsonify({
            'valid': False,
            'error': str(e),
            'message': 'Erro interno na verificação.'
        }), 400


if __name__ == '__main__':
    socketio.run(app, debug=True, use_reloader=False)

