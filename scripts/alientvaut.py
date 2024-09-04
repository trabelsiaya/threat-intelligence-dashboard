import requests
import mysql.connector
from mysql.connector import Error

# Clé API pour l'authentification
API_KEY = 'votre_api_key'  # Remplacez par votre clé API d'AlienVault OTX

# En-têtes pour les requêtes HTTP
HEADERS = {
    'X-OTX-API-KEY': API_KEY
}

# URL de base de l'API
BASE_URL = 'https://otx.alienvault.com/api/v1/'

# Connexion à la base de données MySQL
try:
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="ecrire_votre_mot_de_passe",
        database="threat_intelligence"
    )
    cursor = db.cursor()
    print("Connexion à la base de données réussie.")
except Error as e:
    print(f"Erreur lors de la connexion à la base de données: {e}")
    exit(1)

# Fonction pour insérer les données dans la table Pulses
def insert_pulse(pulse):
    try:
        insert_query = """
        INSERT INTO Pulses (pulse_key, name, description, author_name, created, modified, tlp, adversary)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (
            pulse["id"], pulse["name"], pulse["description"], pulse["author_name"],
            pulse["created"], pulse["modified"], pulse.get("tlp", ""), pulse.get("adversary", "")
        ))
        db.commit()
        print(f"Pulse {pulse['id']} insérée avec succès.")
    except Error as e:
        print(f"Erreur lors de l'insertion de la pulse {pulse['id']}: {e}")

# Fonction pour insérer les IoCs (indicateurs) dans la table PulseIndicators
def insert_pulse_indicators(indicators):
    try:
        for indicator in indicators["results"]:
            insert_query = """
            INSERT INTO PulseIndicators (pulse_key, indicator, type, created, is_active, role)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (
                indicator["pulse_key"], indicator["indicator"], indicator["type"],
                indicator["created"], indicator["is_active"], indicator.get("role", "")
            ))
        db.commit()
        print(f"Indicateurs de la pulse {indicators['results'][0]['pulse_key']} insérés avec succès.")
    except Error as e:
        print(f"Erreur lors de l'insertion des indicateurs: {e}")

# Fonction pour insérer les techniques d'attaque dans la table AttackTechniques
def insert_attack_techniques(attack_techniques, pulse_key):
    try:
        for technique in attack_techniques:
            insert_query = """
            INSERT INTO AttackTechniques (technique_code, pulse_key)
            VALUES (%s, %s)
            """
            cursor.execute(insert_query, (technique, pulse_key))
        db.commit()
        print(f"Techniques d'attaque pour la pulse {pulse_key} insérées avec succès.")
    except Error as e:
        print(f"Erreur lors de l'insertion des techniques d'attaque: {e}")

# Fonction pour récupérer les pulses avec pagination et timeout
def get_pulses(page=1, limit=10, timeout=10):
    url = f"{BASE_URL}pulses/subscribed?page={page}&limit={limit}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout)
        response.raise_for_status()  # Vérifier que la requête s'est bien passée
        return response.json()
    except requests.exceptions.Timeout:
        print(f"Erreur de timeout lors de la récupération des pulses à la page {page}.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des pulses à la page {page} : {e}")
        return None

# Fonction pour récupérer les IoCs d'une pulse donnée avec timeout
def get_iocs(pulse_id, timeout=10):
    url = f"{BASE_URL}pulses/{pulse_id}/indicators"
    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout)
        response.raise_for_status()  # Vérifier que la requête s'est bien passée
        data = response.json()
        if data.get('results'):
            return data
        else:
            print(f"Aucun IoC disponible pour le pulse {pulse_id}")
            return None
    except requests.exceptions.Timeout:
        print(f"Erreur de timeout lors de la récupération des IoCs pour le pulse {pulse_id}.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des IoCs pour le pulse {pulse_id} : {e}")
        return None

# Fonction pour récupérer les techniques d'attaque associées à une pulse avec timeout
def get_attack_techniques(pulse_id, timeout=10):
    url = f"{BASE_URL}pulses/{pulse_id}"
    try:
        response = requests.get(url, headers=HEADERS, timeout=timeout)
        response.raise_for_status()  # Vérifier que la requête s'est bien passée
        return response.json().get('attack_ids', [])
    except requests.exceptions.Timeout:
        print(f"Erreur de timeout lors de la récupération des techniques d'attaque pour le pulse {pulse_id}.")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Erreur lors de la récupération des techniques d'attaque pour le pulse {pulse_id} : {e}")
        return None

# Fonction principale qui gère l'extraction et l'enregistrement des données
def main():
    page = 1
    limit = 10

    while True:
        pulses_data = get_pulses(page=page, limit=limit)
        if pulses_data and pulses_data.get('results'):
            for pulse in pulses_data.get('results', []):
                pulse_id = pulse.get('id')

                # Insertion des données de la pulse dans la table Pulses
                insert_pulse(pulse)

                # Récupérer et insérer les IoCs dans la table PulseIndicators
                ioc_data = get_iocs(pulse_id)
                if ioc_data:
                    insert_pulse_indicators(ioc_data)

                # Récupérer et insérer les techniques d'attaque dans la table AttackTechniques
                attack_techniques_data = get_attack_techniques(pulse_id)
                if attack_techniques_data:
                    insert_attack_techniques(attack_techniques_data, pulse_id)

            # Passer à la page suivante
            page += 1
        else:
            print("Toutes les pulses disponibles ont été récupérées.")
            break

if __name__ == "__main__":
    main()

    # Fermeture de la connexion à la base de données
    cursor.close()
    db.close()
