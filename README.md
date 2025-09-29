# Chat de Mensagens Assinadas

Uma aplicação web de chat em tempo real (Flask + Socket.IO) cujas mensagens são **assinadas digitalmente**. Ideal para quem quer aprender ou prototipar mecanismos de verificação de integridade e autenticidade em mensagens, além de explorar integração com IA generativa (LLMs).

---

## Descrição

Este projeto permite aprender e demonstrar assinaturas digitais (PSS/RSA) aplicadas a mensagens em chat em tempo real. Tanto o cliente quanto o bot têm suas mensagens assinadas, garantindo autenticidade e integridade. Um endpoint `/verify` permite verificar assinaturas do bot.

---

## Tecnologias

- Python 3.11+  
- Flask  
- Flask-SocketIO  
- python-socketio  
- Algoritmo de assinatura RSA-PSS em `signature.py`)  
- Front-end simples com HTML, CSS, JavaScript e servidor python usando Socket.IO

---

## Estrutura do Projeto
project/
├─ app.py
├─ bot.py
├─ utils.py
├─ signature.py
├─ requirements.txt
├─ templates/
│ └─ index.html
└─ static/
├─ chat.js
└─ style.css


---

## Instalação e Execução

### Pré-requisitos

- Python 3.11+ instalado  
- Recomenda-se usar ambiente virtual

### No Linux / macOS

bash
cd /caminho/para/project
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# (Opcional) Definir variáveis de ambiente:
- export FLASK_ENV=development
- export SECRET_KEY='sua_chave_secreta'


python app.py
---
No Windows (PowerShell)
- powershell
- Copiar
- Editar
- cd C:\caminho\para\project
- python -m venv .venv
- .venv\Scripts\Activate.ps1
- pip install -r requirements.txt
- python app.py
- Abra no navegador:
- Copiar
- Editar
- http://localhost:5000

---

# Como Testar:
- Funcionamento do Chat

Abra duas abas no navegador em http://localhost:5000

Envie uma mensagem de uma das abas

A mensagem assinada aparece abaixo da mensagem do servidor/bot e no terminal vscode onde roda a aplicação

A resposta do bot aparece apenas na aba que enviou


# Detalhes de Implementação

- signature.py:
contém a classe DigitalSignature com métodos pss_sign(message, private_key) e pss_verify(message, signature_b64, public_key). Em produção, não gere chaves em memória — use arquivos PEM ou um cofre seguro.

- utils.send_signed_message: 
algumas versões do Flask-SocketIO não aceitam broadcast=True. Se ocorrer TypeError: Server.emit() got an unexpected keyword argument 'broadcast', utilize chamada sem este parâmetro ou implementações de fallback.

Proteja segredos e tokens usando variáveis de ambiente ou arquivos de configuração seguros. Evite expor chaves no código.

# Segurança e Boas Práticas

Armazene chaves privadas com segurança (HSM ou arquivos com permissão restrita)

Use HTTPS em produção para garantir confidencialidade além da integridade

Adicione autenticação e rate limiting especialmente para /verify

Você pode estender o bot para usar modelos de linguagem (LLMs), implementando llm.py com funções como:

def ask_llm(prompt: str) -> str:

Faz requisição ao modelo de sua escolha e retorna a resposta em texto

No fluxo de handle_message, chame ask_llm dentro de try/except antes de assinar e enviar a resposta.
<img width="1856" height="951" alt="Tela inicial" src="https://github.com/user-attachments/assets/97308c84-c780-456a-9f06-299f90a477c3" />
<img width="1591" height="324" alt="verificação valida" src="https://github.com/user-attachments/assets/01db8ec2-244d-4591-9dde-ceb425bac38d" />

Após verificada a assinatura e validada
<img width="1859" height="947" alt="assinatura verde" src="https://github.com/user-attachments/assets/2b362acf-df0c-4110-a075-41bdd11416d9" />
<img width="1591" height="324" alt="verificação valida" src="https://github.com/user-attachments/assets/d96e8f6f-0d54-42ee-8a01-44c820d95911" />

Caso inválida
<img width="1863" height="948" alt="sistema invadido" src="https://github.com/user-attachments/assets/afdf2179-14db-4ff8-b21f-f5022245392a" />
<img width="1602" height="736" alt="assinatura invalida" src="https://github.com/user-attachments/assets/b5788f7f-b189-4602-9b43-e390a36e0979" />


assinatura completa
<img width="1601" height="736" alt="assinatura terminal" src="https://github.com/user-attachments/assets/4a9cdde2-b434-40d3-bfcf-193fa5eeb1f4" />

