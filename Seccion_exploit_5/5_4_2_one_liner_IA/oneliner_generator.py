import tkinter as tk
from tkinter import filedialog
from openai import OpenAI
from dotenv import load_dotenv

# Carga variables de entorno desde un archivo .env
load_dotenv()

class OpenAIGenerator:
    """
    Clase que encapsula la funcionalidad para generar texto usando la API de OpenAI.

    Attributes:
        client (OpenAI): Cliente de la API de OpenAI.
        model_name (str): Nombre del modelo de IA a utilizar.
    """

    def __init__(self, model_name='gpt-4-0125-preview'):
        """
        Inicializa la instancia de OpenAIGenerator con un modelo específico.

        Args:
            model_name (str): El nombre del modelo a utilizar, por defecto 'gpt-4-0125-preview'.
        """
        self.client = OpenAI()
        self.model_name = model_name

    def generate(self, prompt):
        """
        Genera una respuesta del modelo de OpenAI basado en el prompt proporcionado.

        Args:
            prompt (str): El texto prompt que se envía al modelo.

        Returns:
            str: El texto generado por el modelo de IA.
        """
        response = self.client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=self.model_name
        )
        return response.choices[0].message.content

def generate_oneliner(generator, prompt, code):
    """
    Función que genera un oneliner basado en un prompt y código dado, utilizando un generador.

    Args:
        generator (OpenAIGenerator): El generador que utiliza la API de OpenAI.
        prompt (str): El prompt a procesar.
        code (str): El código fuente sobre el que se realizará la consulta.

    Returns:
        str: El oneliner generado o None si hay un error.
    """
    prompt = f"{prompt}:\n{code}"
    try:
        return generator.generate(prompt)
    except Exception as e:
        print(f"Error al generar el oneliner: {e}")
        return None
    
def select_file():
    """
    Abre un diálogo para seleccionar un archivo y devuelve la ruta al archivo seleccionado.

    Returns:
        str: La ruta del archivo seleccionado.
    """
    root = tk.Tk()
    root.withdraw()
    file_path = filedialog.askopenfilename()
    return file_path

if __name__ == "__main__":
    file_path = select_file()
    if file_path:
        with open(file_path) as file:
            content = file.read()
        generator = OpenAIGenerator()
        prompt = "Teniendo en cuenta el código que se proporciona a continuación, convierte el código en una versión compatible con Python 2. Una vez hecho esto, convierte el código compatible con Python 2 en un one-liner"
        oneliner = generate_oneliner(generator, prompt, content)
        print(oneliner)