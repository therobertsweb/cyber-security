import re
import subprocess
from collections import namedtuple

class WifiPasswordCollector:
    """Clase para recopilar contraseñas de redes Wi-Fi guardadas en un sistema Windows.
    
    Atributos:
        verbose (int): Nivel de verbosidad. Si es 1, se imprimen los detalles de los perfiles.
    """

    def __init__(self, verbose=1):
        """Inicializa una instancia de WifiPasswordCollector.

        Args:
            verbose (int): Nivel de verbosidad. Por defecto es 1.
        """
        self.verbose = verbose

    def get_windows_profiles(self):
        """Obtiene los perfiles de redes Wi-Fi guardados en el sistema Windows.

        Returns:
            list: Lista de tuplas namedtuple 'Profile' con los detalles de los perfiles.
        """
        Profile = namedtuple("Profile", ["ssid", "ciphers", "key"])
        profiles = []

        ssids = self._get_windows_saved_ssids()

        for ssid in ssids:
            try:
                ssid_details = subprocess.check_output(f'netsh wlan show profile "{ssid}" key=clear').decode('cp1252')
            except UnicodeDecodeError:
                continue  # En caso de error, salta al siguiente perfil

            key = next((k.strip().strip(":").strip() for k in re.findall(r"Contenido de la clave(.*)", ssid_details)), "None")
            ciphers = "/".join([c.strip().strip(":").strip() for c in re.findall(r"Cifrado(.*)", ssid_details)])
            profile = Profile(ssid=ssid, ciphers=ciphers, key=key)
            profiles.append(profile)
            if self.verbose:
                self._print_profile(profile)
        return profiles

    def _get_windows_saved_ssids(self):
        """Obtiene las SSID de los perfiles de redes Wi-Fi guardados en el sistema Windows.

        Returns:
            list: Lista de SSIDs guardadas.
        """
        output = subprocess.check_output("netsh wlan show profiles").decode()
        return [profile.strip().strip(":").strip() for profile in re.findall(r"Perfil de todos los usuarios(.*)", output)]
    
    def _print_profile(self, profile):
        """Imprime los detalles del perfil en formato legible.

        Args:
            profile (namedtuple): Tupla 'Profile' con los detalles del perfil.
        """
        if isinstance(profile, tuple) and hasattr(profile, '_fields'):
            if 'ciphers' in profile._fields:
                print(f"{profile.ssid:25}{profile.ciphers:15}{profile.key:50}")
            else:
                print("El perfil no se ha leído correctamente.")

if __name__ == "__main__":
    collector = WifiPasswordCollector(verbose=1)
    profiles = collector.get_windows_profiles()
