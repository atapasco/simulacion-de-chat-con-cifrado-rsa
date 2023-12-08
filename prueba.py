import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QLabel
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import requests

def generate_key_pair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/claves raul/private_key.pem", "wb") as private_key_file:
        private_key_file.write(private_pem)

    with open("C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/claves raul/public_key.pem", "wb") as public_key_file:
        public_key_file.write(public_pem)

def cifrar_archivo(archivo_origen, archivo_cifrado, clave_publica_path):
    with open(clave_publica_path, "rb") as f:
        clave_publica_pem = f.read()

    with open(archivo_origen, "rb") as f:
        datos = f.read()

    clave_publica = serialization.load_pem_public_key(clave_publica_pem)
    ciphertext = clave_publica.encrypt(
        datos,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(archivo_cifrado, "wb") as f:
        f.write(ciphertext)

def descifrar_archivo(archivo_cifrado, archivo_descifrado, clave_privada_path):
    with open(clave_privada_path, "rb") as f:
        clave_privada_pem = f.read()

    with open(archivo_cifrado, "rb") as f:
        datos_cifrados = f.read()

    clave_privada = serialization.load_pem_private_key(clave_privada_pem, password=None)

    plaintext = clave_privada.decrypt(
        datos_cifrados,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(archivo_descifrado, "wb") as f:
        f.write(plaintext)



class ChatApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Chat')
        self.setGeometry(100, 100, 400, 500)

        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout()

        self.barra_superior = QLabel('Raul', self)
        self.barra_superior.setAlignment(Qt.AlignCenter)
        self.barra_superior.setStyleSheet('background-color: #3498db; color: white; font-size: 15px; padding: 3px;')
        self.layout.addWidget(self.barra_superior)

        self.chat_display = QTextEdit()
        self.chat_display.setReadOnly(True)

        
        self.send_button = QPushButton('recibir')
        self.send_button.clicked.connect(self.recibir_mensaje)

        self.layout.addWidget(self.chat_display)
        
        self.layout.addWidget(self.send_button)

        self.central_widget.setLayout(self.layout)

    def recibir_mensaje(self):
        
        archivo_descifrado = "C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/carpeta de archivos/resultado/archivo.txt"
        clave_privada_path = "C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/claves paco/private_key.pem"

        url2 = "http://localhost:5000/leer_datos"
        
        local_file = 'datos.bin' # Definimos el nombre del archivo local a guardar
        data = requests.get(url2) # Se envía la solicitud HTTP GET y se obtiene el contenido del archivo
        with open(local_file, 'wb') as file: # Se abre el archivo local en modo escritura binaria
            file.write(data.content)
        
        descifrar_archivo(local_file, archivo_descifrado, clave_privada_path)

        with open("C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/carpeta de archivos/resultado/archivo.txt", "r") as archivo: # Abrimos el archivo en modo de lectura
            for linea in archivo: # Recorremos cada línea del archivo
                self.chat_display.append(f'Raul: {linea.strip()}')
            
        

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ChatApp()
    window.show()
    sys.exit(app.exec_())
        




