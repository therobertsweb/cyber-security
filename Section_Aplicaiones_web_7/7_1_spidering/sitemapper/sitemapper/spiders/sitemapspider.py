import scrapy
import networkx as nx
from urllib.parse import urljoin
from pyvis.network import Network

class SiteMapSpider(scrapy.Spider):
    """
    Spider de Scrapy para generar un mapa de sitio de un sitio web específico.

    Atributos:
        name (str): Nombre del spider.
        allowed_domains (list): Lista de dominios permitidos para el spider.
        start_urls (list): Lista de URLs de inicio para el spider.
        tree (networkx.DiGraph): Grafo dirigido que representa la estructura del sitio web.
    """
    name = "sitemapper"
    allowed_domains = ["192.168.138.129"]
    start_urls = ["http://192.168.138.129:1336/index.php"]

    def __init__(self):
        """Inicializa el spider y el grafo dirigido."""
        super().__init__()
        self.tree = nx.DiGraph()

    def parse(self, response):
        """
        Analiza la respuesta HTTP y construye el grafo del sitio web.

        Args:
            response (scrapy.http.Response): Respuesta de Scrapy que contiene el HTML de la página.
        """
        current_url = response.url
        self.tree.add_node(current_url, title=response.css('title::text').get())

        for href in response.css('a::attr(href)').getall():
            full_url = urljoin(current_url, href)
            if not self.tree.has_edge(current_url, full_url):
                self.tree.add_edge(current_url, full_url)
                yield scrapy.Request(full_url, callback=self.parse)

    def closed(self, reason):
        """
        Método que se llama cuando el spider se cierra. Genera y guarda el grafo interactivo.

        Args:
            reason (str): Razón por la que el spider se cerró.
        """
        self.draw_interactive_graph(self.tree)

    def draw_interactive_graph(self, graph):
        """
        Dibuja el grafo interactivo y lo guarda como un archivo HTML.

        Args:
            graph (networkx.DiGraph): Grafo dirigido que representa la estructura del sitio web.
        """
        net = Network(height="750px", width="100%", bgcolor="#222222", font_color="white", directed=True)
        net.from_nx(graph)

        # Configurar las físicas
        net.repulsion(node_distance=200, central_gravity=0.3, spring_length=200, spring_strength=0.05, damping=0.09)

        # Incluir un botón para desactivar las físicas
        net.toggle_physics(True)  # True inicia las físicas activadas

        for node in graph.nodes:
            node_url = node
            html_link = f"<a href='{node_url}' target='_blank'>{node_url}</a>"
            net.get_node(node)["title"] = html_link

        # Guardar y mostrar el grafo interactivo
        net.show("sitemap.html", notebook=False)