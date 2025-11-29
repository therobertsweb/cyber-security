# -*- coding: utf-8 -*-
from burp import IBurpExtender
from burp import IHttpListener

class BurpExtender(IBurpExtender, IHttpListener):
    """Implementa IBurpExtender e IHttpListener para automatizar la manipulación de solicitudes HTTP en Burp Suite."""

    def registerExtenderCallbacks(self, callbacks):
        """Registra la extensión y establece los callbacks necesarios.

        Args:
            callbacks: Instancia de IBurpExtenderCallbacks para registrar los callbacks de la extensión.
        """
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # Establecemos el nombre de la extensión
        callbacks.setExtensionName("HTTP Requests Automation")

        # Registramos el HttpListener para interceptar solicitudes y respuestas HTTP
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """Procesa los mensajes HTTP interceptados por Burp Suite.

        Args:
            toolFlag: Indicador del tipo de herramienta que generó el mensaje.
            messageIsRequest: Booleano que indica si el mensaje es una solicitud (True) o una respuesta (False).
            messageInfo: Instancia de IHttpRequestResponse que contiene los detalles del mensaje HTTP.
        """
        # Solo procesamos respuestas
        if not messageIsRequest:
            # Obtener los datos de la respuesta
            response = messageInfo.getResponse()
            # Convertir bytes a string
            response_info = self._helpers.analyzeResponse(response)
            headers = response_info.getHeaders()

            # Imprimir las cabeceras
            print("\nResponse headers:")
            for header in headers:
                print(header)
            
            # Extraer el contenido de la respuesta
            body_offset = response_info.getBodyOffset()
            body = response[body_offset:]
            body_string = self._helpers.bytesToString(body)

            # Imprimir el cuerpo de la respuesta
            print("\nResponse body:")
            print(body_string)