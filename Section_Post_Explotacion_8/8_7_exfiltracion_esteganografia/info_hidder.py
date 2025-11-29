import cv2
import argparse
from bitarray import bitarray

class InfoHidder:
    """Clase para ocultar y revelar información en imágenes usando LSB (Least Significant Bit).
    
    Args:
        nombre_imagen (str): Ruta del archivo de imagen en la que se va a ocultar la información.
    """

    def __init__(self, nombre_imagen):
        self.imagen = cv2.imread(nombre_imagen)
        self.n_bytes = self.imagen.size // 8
        print(f"Máximo número de bytes a codificar: {self.n_bytes}")

    def a_binario(self, datos):
        """Convierte datos a una representación binaria.

        Args:
            datos (str o bytes): Datos a convertir a binario.

        Returns:
            bitarray: Representación binaria de los datos.
        """
        ba = bitarray()
        ba.frombytes(datos.encode() if isinstance(datos, str) else bytes(datos))
        return ba

    def codificar(self, datos_secretos):
        """Codifica un mensaje secreto en la imagen.

        Args:
            datos_secretos (str): Mensaje secreto a codificar.

        Raises:
            ValueError: Si la imagen no tiene suficientes bytes para codificar el mensaje.
        """
        if len(datos_secretos) > self.n_bytes:
            raise ValueError("Bytes insuficientes, se necesita una imagen más grande.")
        
        datos_binarios = self.a_binario(f"{datos_secretos}====")
        longitud_datos = len(datos_binarios)
        indice_datos = 0
        
        for pixel in self.imagen.reshape(-1, 3):
            for i in range(3):
                if indice_datos >= longitud_datos:
                    break
                # Modifica el bit menos significativo del píxel
                pixel[i] = (pixel[i] & ~1) | datos_binarios[indice_datos]
                indice_datos += 1
            if indice_datos >= longitud_datos:
                break

    def guardar_imagen(self, nombre_salida):
        """Guarda la imagen modificada con el mensaje codificado.

        Args:
            nombre_salida (str): Nombre del archivo de imagen de salida.
        """
        cv2.imwrite(nombre_salida, self.imagen)

    def decodificar(self):
        """Decodifica el mensaje secreto de la imagen.

        Returns:
            str: Mensaje secreto decodificado.
        """
        datos_binarios = bitarray()
        datos_binarios.extend((pixel & 1 for pixel in self.imagen.reshape(-1, 3).ravel()))
        datos_decodificados = datos_binarios.tobytes().decode(errors='ignore')
        return datos_decodificados.split("====", 1)[0]

def main():
    """Función principal para manejar la codificación y decodificación de mensajes en imágenes."""
    parser = argparse.ArgumentParser(description="Codifica y decodifica mensajes secretos en imágenes.")
    parser.add_argument("accion", choices=["codificar", "decodificar"], help="Elige entre 'codificar' o 'decodificar'.")
    parser.add_argument("nombre_entrada", help="Nombre del archivo de imagen de entrada.")
    parser.add_argument("--mensaje", help="Mensaje secreto a codificar")
    parser.add_argument("--nombre-salida", help="Nombre del archivo de imagen de salida.")

    args = parser.parse_args()

    hidder = InfoHidder(args.nombre_entrada)

    if args.accion == 'codificar':
        if not args.mensaje:
            parser.error("Debe proporcionar un mensaje secreto a codificar.")
        hidder.codificar(args.mensaje)
        hidder.guardar_imagen(args.nombre_salida or "imagen_codificada.png")
    elif args.accion == 'decodificar':
        datos_decodificados = hidder.decodificar()
        print(f"Datos decodificados: {datos_decodificados}")

if __name__ == "__main__":
    main()