import base64
import hashlib
from flask import Flask, render_template, request, jsonify # Adicionado jsonify
from flask_socketio import SocketIO, emit
import time
import random
from signature import DigitalSignature  # Importa a classe de assinatura

# Configuração do Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = 'seguranca2025!' # Use uma chave mais robusta em produção
socketio = SocketIO(app, cors_allowed_origins="*")

# Inicializa o sistema de assinatura digital
# Isso gera as chaves RSA para o bot e para um usuário de exemplo
signature_system = DigitalSignature()

# --- Gerenciamento de Estado do Usuário ---
# Dicionário para armazenar o estado de cada usuário conectado (por session ID do SocketIO)
# Em uma aplicação real, isso seria um banco de dados para persistir os dados.
user_states = {}

def get_user_state(sid):
    """
    Retorna o estado do usuário associado a um Session ID (sid).
    Se o sid não existir, um estado padrão é criado e retornado.
    """
    if sid not in user_states:
        user_states[sid] = {'name': 'Visitante', 'last_interaction': time.time()}
    return user_states[sid]

def update_user_state(sid, key, value):
    """
    Atualiza uma propriedade específica no estado do usuário e o timestamp da última interação.
    """
    state = get_user_state(sid)
    state[key] = value
    state['last_interaction'] = time.time()

# --- Lógica de Comandos do Bot ---
# Funções que implementam a lógica para cada comando do bot.
# Cada função recebe o 'sid' (para acessar o estado do usuário) e a 'message_text' completa.

def handle_help(sid, message_text):
    """Lida com o comando /ajuda, listando os comandos disponíveis para o usuário."""
    return "Comandos disponíveis: /ola, /ajuda, /nome [seu nome], /meunome."

def handle_greeting(sid, message_text):
    """Lida com o comando /ola e sauda o usuário pelo nome (se já tiver sido definido)."""
    user_state = get_user_state(sid)
    name = user_state['name']
    greetings = [
        f"Olá, {name}! Como posso ajudar?",
        f"Oi, {name}! É um prazer falar com você.",
        f"E aí, {name}? Tudo bem?"
    ]
    return random.choice(greetings)

def handle_set_name(sid, message_text):
    """
    Lida com o comando /nome [seu nome], permitindo ao usuário definir seu nome.
    O nome é extraído da mensagem e armazenado no estado da sessão.
    """
    parts = message_text.split(' ', 1) # Divide a mensagem em no máximo 2 partes: comando e o resto
    if len(parts) > 1:
        new_name = parts[1].strip() # Pega a segunda parte como o nome
        if new_name:
            update_user_state(sid, 'name', new_name) # Atualiza o estado do usuário
            return f"Entendido! De agora em diante, vou te chamar de {new_name}."
    return "Para definir seu nome, use: /nome [seu nome]"

def handle_get_name(sid, message_text):
    """Lida com o comando /meunome, informando o nome atual do usuário."""
    user_state = get_user_state(sid)
    name = user_state['name']
    if name == 'Visitante':
        return "Você ainda não me falou seu nome. Use /nome [seu nome] para definir."
    return f"Seu nome é: {name}"

# Mapeia os comandos de texto para as funções Python correspondentes.
bot_commands = {
    "/ajuda": handle_help,
    "/ola": handle_greeting,
    "/nome": handle_set_name,
    "/meunome": handle_get_name
}

def process_message_for_bot(sid, message):
    """
    Processa a mensagem do usuário para determinar a resposta do bot.
    Verifica se a mensagem é um comando ou uma mensagem geral.
    """
    message_lower = message.lower().strip()
    if message_lower.startswith('/'):
        cmd = message_lower.split(' ')[0] # Extrai o comando
        if cmd in bot_commands:
            # Chama a função de manipulação de comando mapeada
            return bot_commands[cmd](sid, message)
        return "Comando desconhecido. Digite /ajuda para ajuda."
    
    # Respostas para mensagens que não são comandos
    if "olá" in message_lower or "oi" in message_lower:
        return handle_greeting(sid, message)
    elif "como você está" in message_lower:
        return "Eu sou um programa de computador, então estou sempre bem! E você?"
    elif "obrigado" in message_lower or "valeu" in message_lower:
        return "De nada! Fico feliz em ajudar."
    else:
        # Resposta padrão para qualquer outra mensagem
        return f"Utilize algum comando disponível:\n /ola, /ajuda, /nome [seu nome], /meunome."


# --- Rotas e Eventos do SocketIO ---

@app.route('/')
def index():
    """
    Rota principal que renderiza a página HTML do chat.
    """
    return render_template('index.html')

@socketio.on('connect')
def handle_connect():
    """
    Evento disparado quando um novo cliente se conecta ao SocketIO.
    Envia uma mensagem de boas-vindas do bot ao cliente que acabou de conectar.
    """
    sid = request.sid
    user_state = get_user_state(sid)
    print(f'Cliente conectado! SID: {sid}, Nome: {user_state["name"]}')
    
    # Mensagem de boas-vindas do bot (não assinada, pois é uma mensagem de sistema inicial)
    emit('resposta', {
        'sender': 'Bot',
        'content': f'Bem-vindo, {user_state["name"]}! Digite /ajuda para visualizar os comandos disponíveis.',
        'signature': 'N/A', # Não há assinatura para esta mensagem de sistema
        'isUser': False
    }, room=sid)

@socketio.on('disconnect')
def handle_disconnect():
    """
    Evento disparado quando um cliente se desconecta do SocketIO.
    """
    sid = request.sid
    # Opcional: Remover o estado do usuário se a sessão não precisar ser persistente
    # user_states.pop(sid, None)
    print(f'Cliente desconectado! SID: {sid}')

@socketio.on('mensagem') # Ouve o evento 'mensagem' enviado pelo cliente (do input do usuário)
def handle_message(message_text): # O 'data' do cliente é agora 'message_text' diretamente
    """
    Evento disparado quando o cliente envia uma mensagem (evento 'mensagem').
    Esta função assina a mensagem do usuário, a re-emite para todos,
    processa a resposta do bot, assina a resposta do bot e a envia de volta.
    """
    sid = request.sid
    user_name = get_user_state(sid)['name'] # Pega o nome do usuário para exibir

    # --- DEBUG: Imprime a mensagem do usuário recebida no servidor ---
    print(f"DEBUG (Servidor): Mensagem recebida de '{user_name}' (SID: {sid}): '{message_text}'")

    # 1. Assina a mensagem do usuário (usando a chave privada do usuário)
    # A função pss_sign agora retorna apenas a assinatura (salt é interno)
    user_signature_b64, _ = signature_system.pss_sign(message_text, signature_system.user_private)
    
    # 2. Re-emite a mensagem do usuário (assinada) para TODOS os clientes
    # Isso garante que a mensagem do usuário apareça para todos no chat.
    emit('resposta', {
        'sender': user_name, # Exibe o nome do usuário
        'content': message_text,
        'signature': user_signature_b64,
        'isUser': True
    }, broadcast=True)

    # 3. Processa a mensagem com a lógica do bot para obter a resposta
    bot_response_text = process_message_for_bot(sid, message_text)

    # --- DEBUG: Imprime a resposta do bot antes de ser enviada ---
    print(f"DEBUG (Servidor): Resposta do bot (antes de emitir): '{bot_response_text}'")

    # Simula um pequeno atraso para a resposta do bot (opcional, para parecer mais natural)
    time.sleep(0.5)

    # 4. Assina a resposta do bot (usando a chave privada do bot)
    bot_signature_b64, _ = signature_system.pss_sign(bot_response_text, signature_system.bot_private)
    
    # 5. Envia a resposta do bot (assinada) APENAS para o cliente que enviou a mensagem original
    # Se quiser que todos vejam a resposta do bot, mude 'room=sid' para 'broadcast=True'.
    emit('resposta', {
        'sender': 'Bot',
        'content': bot_response_text,
        'signature': bot_signature_b64,
        'isUser': False
    }, room=sid)

@app.route('/verify', methods=['POST'])
def verify_signature_route(): # Renomeado para evitar conflito com 'verifySignature' no JS
    """
    Rota HTTP para verificar uma assinatura digital.
    Recebe a mensagem e a assinatura (e opcionalmente o salt, embora não seja mais usado externamente).
    """
    try:
        data = request.get_json()
        message = data['message']
        signature_b64 = data['signature']
        # salt = data.get('salt', '') # Salt não é mais necessário ser enviado separadamente

        # Determina qual chave pública usar para verificação
        # Se a mensagem foi enviada pelo 'Bot', verifica com a chave pública do bot.
        # Caso contrário (se for uma mensagem de usuário), verifica com a chave pública do usuário.
        # Para simplificar, vou assumir que estamos verificando mensagens do bot aqui,
        # pois o botão de verificar está apenas nas mensagens do bot.
        # Em um sistema real, você precisaria de um mecanismo para saber quem assinou.
        
        # Para este exemplo, vamos verificar com a chave pública do bot,
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
            'error': str(e)
        }), 400
    
if __name__ == '__main__':
    # use_reloader=False é recomendado quando se usa SocketIO com debug=True
    # para evitar problemas de duplicação de processos.
    socketio.run(app, debug=True, use_reloader=False)