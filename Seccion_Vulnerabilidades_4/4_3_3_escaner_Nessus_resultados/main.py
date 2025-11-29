from nessus_scanner import NessusScanner
import pandas

def main():
    # Instancia del objeto NessusScanner para interactuar con Nessus
    scanner_nessus = NessusScanner()
    
    # Exporta el escaneo con ID 7 en formato CSV
    scanner_nessus.export_scan(7, "csv")
    
    # Las siguientes líneas están comentadas para no ejecutar la lectura y visualización del archivo exportado
    # df = pandas.read_csv("/home/kali/python_hacking/seccion4/4_3_Nessus_scanner/scan_7_export.pdf", encoding='latin')
    # print(df)

if __name__ == "__main__":
    main()


