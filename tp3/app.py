from flask import Flask, render_template
from flask_socketio import SocketIO, emit




app = Flask(__name__)
app.config['SECRET_KEY'] = 'seu-segredo-aqui'
socketio = SocketIO(app)

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('mensagem')
def handle_message(data):
    print('recebido:', data)         # mostra no servidor
    emit('resposta', {'data': data}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True)
