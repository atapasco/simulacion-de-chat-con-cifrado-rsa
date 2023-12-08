import os
from flask import Flask, request, jsonify
from flask import send_file

app = Flask(__name__)


@app.route('/leer_claves_publicas_lukas', methods=['GET'])
def leer_claves():
    encrypted_file_path = 'C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/claves paco/public_key.pem'

    if os.path.exists(encrypted_file_path):
        return send_file(
            encrypted_file_path,
            as_attachment=True,
            download_name='archivo_cifrado.txt',
            mimetype='application/octet-stream'
        )
    else:
        return "El archivo cifrado no se encuentra disponible.", 404
    

@app.route('/guardar_datos', methods=['POST'])
def guardar_datos():
    encrypted_file = request.files['archivo']
    if encrypted_file:
        # Guarda el archivo cifrado en una ubicación temporal
        encrypted_file.save('C:/Users/pipet/OneDrive/Documentos/archivo_cifrado.bin')

        return "Archivo cifrado recibido y guardado con éxito."

    return "No se proporcionó un archivo cifrado.", 400

@app.route('/leer_datos', methods=['GET'])
def leer_datos():
    encrypted_file_path = 'C:/Users/pipet/OneDrive/Documentos/archivo_cifrado.bin'

    if os.path.exists(encrypted_file_path):
        return send_file(
            encrypted_file_path,
            as_attachment=True,
            download_name='archivo_cifrado.txt',
            mimetype='application/octet-stream'
        )
    else:
        return "El archivo cifrado no se encuentra disponible.", 404

if __name__ == '__main__':
    app.run(debug=True)