from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

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

if __name__ == "__main__":
    # Ciframos un archivo
    archivo_origen = "C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/carpeta de archivos/texto.txt"
    archivo_cifrado = "C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/carpeta de archivos/archivo.bin"
    clave_publica_path = "C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/claves/public_key.pem"
    cifrar_archivo(archivo_origen, archivo_cifrado, clave_publica_path)

    # Desciframos el archivo
    archivo_descifrado = "C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/carpeta de archivos/archivo.txt"
    clave_privada_path = "C:/Users/pipet/OneDrive/Documentos/proyectos de programacion/proyectos python/simulacion de chat con cifrado rsa/claves/private_key.pem"
    descifrar_archivo(archivo_cifrado, archivo_descifrado, clave_privada_path)