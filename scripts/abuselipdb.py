import requests
import datetime
import mysql.connector
import json

# Étape 1 : Définir la clé API et l'URL de base
API_KEY = 'votre_api_key'  # Remplacez par votre clé API
BASE_URL = 'https://api.abuseipdb.com/api/v2/check-block'

# Étape 2 : Configurer les en-têtes de la requête
headers = {
    'Accept': 'application/json',
    'Key': API_KEY
}

# Étape 3 : Liste des réseaux (plages d'adresses IP) à vérifier
networks = [
    '192.168.0.0/24',  # Exemples de réseaux
    '10.0.0.0/24',
    '172.16.0.0/24'
]

# Fonction pour insérer les données dans les tables MySQL
def insert_into_mysql(data):
    # Connexion à la base de données MySQL
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="ecrire_votre_mot_de_passe",
        database="threat_intelligence"
    )
    cursor = db.cursor()

    # Insertion dans la table AbuseIpReport
    network_address = data['data']['networkAddress']
    netmask = data['data']['netmask']
    min_address = data['data']['minAddress']
    max_address = data['data']['maxAddress']
    num_possible_hosts = data['data']['numPossibleHosts']
    address_space_desc = data['data']['addressSpaceDesc']

    insert_abuse_report_query = """
    INSERT INTO AbuseIpReport (network_address, netmask, min_address, max_address, num_possible_hosts, address_space_desc)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    
    cursor.execute(insert_abuse_report_query, (
        network_address, netmask, min_address, max_address, num_possible_hosts, address_space_desc
    ))
    
    report_id = cursor.lastrowid  # Récupérer l'ID de la dernière insertion

    # Insertion dans la table ReportedIps pour chaque adresse IP signalée
    reported_ips = data['data'].get('reportedAddress', [])
    
    for ip_data in reported_ips:
        ip_address = ip_data.get('ipAddress')
        num_reports = ip_data.get('numReports', 0)
        most_recent_report = ip_data.get('mostRecentReport')
        abuse_confidence_score = ip_data.get('abuseConfidenceScore', 0)
        country_code = ip_data.get('countryCode')

        insert_reported_ips_query = """
        INSERT INTO ReportedIps (ip_address, report_id, num_reports, most_recent_report, abuse_confidence_score, country_code)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        
        cursor.execute(insert_reported_ips_query, (
            ip_address, report_id, num_reports, most_recent_report, abuse_confidence_score, country_code
        ))

    # Commit des modifications
    db.commit()

    # Fermeture de la connexion
    cursor.close()
    db.close()

    print("Les données ont été insérées avec succès dans la base de données.")

# Fonction principale qui gère l'extraction et l'insertion des données
def main():
    # Boucle sur chaque réseau et requête à l'API
    for network in networks:
        params = {'network': network}
        
        response = requests.get(BASE_URL, headers=headers, params=params)
        
        # Vérifier la réponse
        if response.status_code == 200:
            data = response.json()
            insert_into_mysql(data)  # Insérer les données dans MySQL
        else:
            print(f"Erreur lors de la requête pour le réseau {network}: {response.status_code}, {response.text}")

# Exécution du script
if __name__ == "__main__":
    main()
