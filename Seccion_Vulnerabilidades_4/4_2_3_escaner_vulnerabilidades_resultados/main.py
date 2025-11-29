from vulnerability_scanner import VulnerabilityScanner


if __name__ == "__main__":
    scanner = VulnerabilityScanner()
    servicio = "http"
    cves_encontrados = scanner.search_cves(servicio)
    scanner.pretty_print(cves_encontrados)
