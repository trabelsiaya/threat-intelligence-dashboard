import requests
import json
import mysql.connector

# Fonction pour interroger VirusTotal en utilisant l'API
def query_virustotal(api_key, query_value):
    base_url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    params = {'apikey': api_key, 'ip': query_value}
    
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
def insert_into_mysql(data, ip_address):
    # Connexion à la base de données MySQL
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="ecrire_votre_mot_de_passe",
        database="threat_intelligence"
    )
    cursor = db.cursor()

    # Insertion dans la table IpAnalysis
    asn_owner = data.get("as_owner")
    asn = data.get("asn")
    country = data.get("country")

    insert_ip_analysis_query = """
    INSERT INTO IpAnalysis (ip_address, asn_owner, asn, country)
    VALUES (%s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE asn_owner = VALUES(asn_owner), asn = VALUES(asn), country = VALUES(country)
    """
    
    cursor.execute(insert_ip_analysis_query, (
        ip_address, asn_owner, asn, country
    ))

    # Insertion dans la table IpCommunicatingSamples pour chaque sample
    samples = data.get("detected_communicating_samples", [])
    
    for sample in samples:
        date_detected = sample.get("date")
        sha256_hash = sample.get("sha256")
        positives = sample.get("positives", 0)
        total = sample.get("total", 0)
        
        insert_sample_query = """
        INSERT INTO IpCommunicatingSamples (ip_address, sha256_hash, positives, total, date_detected)
        VALUES (%s, %s, %s, %s, %s)
        """
        
        cursor.execute(insert_sample_query, (
            ip_address, sha256_hash, positives, total, date_detected
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
    
    # Demander à l'utilisateur d'entrer l'adresse IP à analyser
    query_value = input("Entrez l'adresse IP à analyser : ")
    
    # Appeler la fonction pour interroger VirusTotal
    data = query_virustotal(api_key, query_value)
    
    if data:
        # Insérer les données dans MySQL
        insert_into_mysql(data, query_value)
