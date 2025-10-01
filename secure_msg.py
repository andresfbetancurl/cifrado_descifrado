#########################################################################
# Programa para cifrar/descifrar mensaes de texto
#########################################################################
#
# Autor: Andrés F Betancur L
# Versión 1.0
# 2022
#
#########################################################################

# -----------------------------
# Importar librerias necesarias
# -----------------------------

import PySimpleGUI as sg
import base64
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature

# -----------------------
# Utilidades para cifrado
# -----------------------

def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key, filename):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, "wb") as f:
        f.write(pem)

def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, "wb") as f:
        f.write(pem)

def load_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())

# -----------------------
# Cifrado / Descifrado
# -----------------------

def encrypt_message(recipient_pubkey, message, sender_priv=None):
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

    enc_key = recipient_pubkey.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    payload = {
        "enc_key": base64.b64encode(enc_key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

    if sender_priv:
        signature = sender_priv.sign(
            ciphertext,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        payload["signature"] = base64.b64encode(signature).decode()

        sender_pub = sender_priv.public_key()
        payload["sender_pub"] = sender_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    return base64.b64encode(json.dumps(payload).encode()).decode()

def decrypt_message(recipient_priv, payload_b64):
    try:
        payload = json.loads(base64.b64decode(payload_b64).decode())
    except Exception:
        return "Invalid payload", False

    enc_key = base64.b64decode(payload["enc_key"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    aes_key = recipient_priv.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return "Decryption failed", False

    sig_valid = None
    if "signature" in payload and "sender_pub" in payload:
        sender_pub = serialization.load_pem_public_key(payload["sender_pub"].encode())
        try:
            sender_pub.verify(
                base64.b64decode(payload["signature"]),
                ciphertext,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            sig_valid = True
        except InvalidSignature:
            sig_valid = False

    return plaintext, sig_valid

# -----------------------
# Interfaz gráfica
# -----------------------

sg.theme("LightBlue2")

layout = [
    [sg.Text("Mensajería segura", font=("Helvetica", 16))],
    [sg.Frame("Administración de llaves", [
        [sg.Button("Generar llaves"), sg.InputText("mi_privada.pem", size=(20,1), key="privfile"), sg.InputText("mi_publica.pem", size=(20,1), key="pubfile")],
        [sg.Text("Cargar mi llave privada:"), sg.Input(key="privpath"), sg.FileBrowse()],
        [sg.Text("Llave pública de interlocutor:"), sg.Input(key="recipub"), sg.FileBrowse()]
    ])],
    [sg.Frame("Cifrado", [
        [sg.Multiline(size=(60,5), key="msg")],#, placeholder="Type your message here...")],
        [sg.Checkbox("Firmar con mi llave privada", key="dosign")],
        [sg.Button("Cifrar"), sg.Multiline(size=(60,5), key="out_enc", disabled=True)]
    ])],
    [sg.Frame("Descifrado", [
        [sg.Multiline(size=(60,5), key="payload")],#, placeholder="Paste payload here...")],
        [sg.Button("Descifrar"), sg.Multiline(size=(60,5), key="out_dec", disabled=True)]
    ])],
    [sg.Button("Salir")]
]

window = sg.Window("POC Mensajería segura", layout, finalize=True)

# -----------------------
# Ejecución del programa
# -----------------------

my_priv, my_pub = None, None
recipient_pub = None

while True:
    event, values = window.read()
    if event in (sg.WIN_CLOSED, "Salir"):
        break

    if event == "Generar llaves":
        priv, pub = generate_rsa_keypair()
        save_private_key(priv, values["privfile"])
        save_public_key(pub, values["pubfile"])
        sg.popup("Llaves generadas y guardadas!")

    if event == "Cifrar":
        if not values["recipub"]:
            sg.popup_error("Por favor seleccione el archivo con la llave pública del receptor")
            continue
        if not os.path.exists(values["recipub"]):
            sg.popup_error("Llave pública del receptor no encontrada")
            continue
        recipient_pub = load_public_key(values["recipub"])

        sender_priv = None
        if values["dosign"] and values["privpath"]:
            sender_priv = load_private_key(values["privpath"])

        message = values["msg"]
        enc = encrypt_message(recipient_pub, message, sender_priv)
        window["out_enc"].update(enc)

    if event == "Descifrar":
        if not values["privpath"]:
            sg.popup_error("Por favor cargue su llave privada")
            continue
        if not os.path.exists(values["privpath"]):
            sg.popup_error("Llave privada no encontrada")
            continue
        my_priv = load_private_key(values["privpath"])

        payload = values["payload"].strip()
        if not payload:
            sg.popup_error("No se ingreso mensaje a descifrar")
            continue
        dec, sig_valid = decrypt_message(my_priv, payload)
        if sig_valid is None:
            msg = dec + "\n\n(Firma: no presente)"
        else:
            msg = dec + f"\n\n(Firma validad: {sig_valid})"
        window["out_dec"].update(msg)

window.close()


