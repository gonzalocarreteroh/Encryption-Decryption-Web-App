from flask import Flask, render_template, request
from encryption import Encryptor, Decryptor
import json

app = Flask(__name__)

@app.route('/')
def index():
    # return main page
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    # Encrypt message
    if request.method == 'POST':
        message = request.form['message']
        # message = request.args.get('message')
        password = request.form['password']
        # password = request.args.get('password')
        encryptor = Encryptor(message, password)
        ciphertext = encryptor.encrypt_message()
        # return ciphertext
        return render_template('encrypt.html', ciphertext=ciphertext)
    
@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        ciphertext = request.form['ciphertext']
        password = request.form['password']
        # data = request.get_json()
        data = json.loads(ciphertext)
        # ciphertext_dict = data["ciphertext"]
        ciphertext_dict = data
        print(ciphertext_dict)
        # password = data['password']
        decryptor = Decryptor(ciphertext_dict, password)
        plaintext = decryptor.decrypt()
        # return plaintext
        return render_template('decrypt.html', plaintext=plaintext)

if __name__ == '__main__':
    app.run(port=8000, debug=True)
