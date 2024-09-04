import requests
import json
import datetime
import mysql.connector

# Fonction pour interroger VirusTotal en utilisant l'API
def query_virustotal(api_key, query_value):
    """
    Cette fonction interroge VirusTotal pour une URL et remplit les tables MySQL en conséquence.
    
    :param api_key: La clé API de VirusTotal.
    :param query_value: L'URL à analyser.
    """
    
    base_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': query_value}
    
    # Effectuer la requête à l'API
    response = requests.get(base_url, params=params)
    
    # Vérifier si la requête est réussie
    if response.status_code == 200:
        data = response.json()  # Convertir la réponse en JSON
        return data
    else:
        print(f"Erreur lors de la requête. Code d'erreur : {response.status_code}")
        return None

# Fonction pour insérer les résultats dans les tables MySQL
def insert_into_mysql(data, query_value, api_key):
    # Connexion à la base de données MySQL
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="ecrire_votre_mot_de_passe",
        database="threat_intelligence"
    )
    cursor = db.cursor()

    # Insertion dans la table UrlsAnalysis
    analysis_url_date = data.get("scan_date")
    filescan_id = data.get("filescan_id")
    permalink = data.get("permalink")
    positives = data.get("positives")
    resource = data.get("resource")
    response_code = data.get("response_code")

    insert_url_analysis_query = """
    INSERT INTO UrlsAnalysis (url, filescan_id, permalink, positives, resource, response_code, analysis_url_date)
    VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    
    cursor.execute(insert_url_analysis_query, (
        query_value, filescan_id, permalink, positives, resource, response_code, analysis_url_date
    ))
    analysis_url_id = cursor.lastrowid  # Récupérer l'ID de la dernière insertion

    # Insertion dans la table UrlScans pour chaque moteur d'analyse
    scans = data.get("scans", {})
    
    for engine, scan_data in scans.items():
        engine_url_files = engine
        detected = scan_data.get("detected", False)
        result = scan_data.get("result", "")
        
        insert_url_scan_query = """
        INSERT INTO UrlScans (engine_url_files, detected, result, analysis_url_id)
        VALUES (%s, %s, %s, %s)
        """
        
        cursor.execute(insert_url_scan_query, (
            engine_url_files, detected, result, analysis_url_id
        ))

    # Commit des modifications
    db.commit()

    # Fermeture de la connexion
    cursor.close()
    db.close()

    print("Les données ont été insérées avec succès dans la base de données.")

# Exécution du script
if __name__ == "__main__":
    # Remplacez ceci par votre clé API VirusTotal
    api_key = 'votre_api_key'
    
    # Entrez l'URL à analyser
    query_value = input("Entrez l'URL à analyser : ")
    
    # Appeler la fonction pour interroger VirusTotal
    data = query_virustotal(api_key, query_value)
    
    if data:
        # Insérer les données dans MySQL
        insert_into_mysql(data, query_value, api_key)
