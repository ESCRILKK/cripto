from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

# Claves y vector de inicialización
LOGIN_KEY = bytes.fromhex('4143435f4d4f565f5353445f32303232')
LOGIN_IV = bytes.fromhex('4d4f565f323032325f4143435f535344')

# Obtener el texto a encriptar del usuario
plaintext = input("Ingrese el texto a encriptar: ")

# Crear un objeto Cipher para encriptar
backend = default_backend()
cipher = Cipher(algorithms.AES(LOGIN_KEY), modes.CBC(LOGIN_IV), backend=backend)
encryptor = cipher.encryptor()

# Asegurar que el texto tiene un tamaño múltiple de 16 bytes
padded_plaintext = plaintext.encode('utf-8') + b' ' * (16 - len(plaintext) % 16)
# Encriptar el texto plano
ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

# Codificar el texto cifrado en base64 para facilitar su impresión y almacenamiento
ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')

print("Texto cifrado en base64:", ciphertext_base64)
