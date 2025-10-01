Aplicación simple con interfaz gráfica para cifrar y descifrar mensajes de texto con llaves públicas y privadas

Para ejecutar el programa:

1. Instalar dependencias:

python -m pip install --extra-index-url https://PySimpleGUI.net/install PySimpleGUI

2. Ejecutar programa (interfaz gráfica):

Ingresar a directorio donde se encuentra el archivo y ejecutar el comando - 
python secure_msg.py

3. Se abre la interfaz gráfica

4. Dar click en Generar llaves (se pueden editar los nombres en las casillas correspondientes)
5. Se debe compartir la llave pública con el interlocutor, ambas partes deben compartir su llave pública.
6. Para cifrar, ingresar mensaje en el campo de cifrado, marcar la casilla para firmar con la llave privada y presionar el botón de cifrar. EL mensaje sicfrado se puede copiar y compartir con el interlocutor.
7. Copiar el mensaje cifrado recibido y pegarlo en la casilla de descifrar, presionar botón para descifrar; se obtiene el mensaje leíble y validación de la firma (llave).

8. Presionar botón Salir para cerrar el programa.
