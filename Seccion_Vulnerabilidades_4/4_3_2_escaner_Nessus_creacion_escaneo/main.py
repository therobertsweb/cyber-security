from nessus_scanner import NessusScanner

def main():
    # Instancia del objeto NessusScanner para interactuar con Nessus
    scanner_nessus = NessusScanner()
    
    # Obtener las politicas
    scanner_nessus.get_policies()

if __name__ == "__main__":
    main()