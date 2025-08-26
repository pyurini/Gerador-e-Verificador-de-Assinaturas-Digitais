# bot.py
import random
from utils import get_user_state, update_user_state

def handle_help(sid, _):
    return "Comandos disponíveis: /ola, /ajuda, /nome [seu nome], /meunome."

def handle_greeting(sid, _):
    name = get_user_state(sid)['name']
    greetings = [
        f"Olá, {name}! Como posso ajudar?",
        f"Oi, {name}! É um prazer falar com você.",
        f"E aí, {name}? Tudo bem?"
    ]
    return random.choice(greetings)

def handle_set_name(sid, message_text):
    parts = message_text.split(' ', 1)
    if len(parts) > 1 and parts[1].strip():
        new_name = parts[1].strip()
        update_user_state(sid, 'name', new_name)
        return f"Entendido! Agora te chamo de {new_name}."
    return "Você ainda não me falou seu nome. Use /nome [seu nome] para definir."

def handle_get_name(sid, _):
    name = get_user_state(sid)['name']
    if name == 'Visitante':
        return "Você ainda não me falou seu nome. Use /nome [seu nome] para definir."
    return f"Seu nome é: {name}"

bot_commands = {
    "/ajuda": handle_help,
    "/ola": handle_greeting,
    "/nome": handle_set_name,
    "/meunome": handle_get_name
}

def process_message(sid: str, message: str) -> str:
    message_lower = message.lower().strip()
    if message_lower.startswith('/'):
        cmd = message_lower.split(' ')[0]
        handler = bot_commands.get(cmd)
        if handler:
            return handler(sid, message)
        return "Comando desconhecido. Digite /ajuda para ajuda."

    if "olá" in message_lower or "oi" in message_lower:
        return handle_greeting(sid, message)
    if "como você está" in message_lower:
        return "Eu sou um programa de computador, então estou sempre bem! E você?"
    if "obrigado" in message_lower or "valeu" in message_lower:
        return "De nada! Fico feliz em ajudar."
    return "Utilize algum comando disponível:\n /ola, /ajuda, /nome [seu nome], /meunome."
