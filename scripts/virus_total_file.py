import requests
import json
import mysql.connector
import datetime

# Fonction pour interroger l'API VirusTotal et insérer les données dans MySQL
def query_and_insert_virustotal(api_key, query_type, query_value, content_file):
    try:
        # Connexion à la base de données MySQL
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='ecrire_votre_mot_de_passe',
            database='threat_intelligence'
        )
        cursor = connection.cursor()

        # Interroger l'API VirusTotal
        base_url = 'https://www.virustotal.com/vtapi/v2/'
        if query_type == 'file':
            url = f"{base_url}file/report"
            params = {'apikey': api_key, 'resource': query_value}
        else:
            print("Type de requête non pris en charge. Utilisez 'file'.")
            return

        response = requests.get(url, params=params)

        if response.status_code == 200:
            data = response.json()

            # Insertion dans la table FilesAnalysis
            insert_file_query = """
            INSERT INTO FilesAnalysis 
            (md5_hash, permalink, positives, resource, response_code, analysis_file_date, content_file) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            file_data = (
                data.get('md5'),
                data.get('permalink'),
                data.get('positives'),
                data.get('resource'),
                data.get('response_code'),
                data.get('scan_date'),
                content_file
            )
            cursor.execute(insert_file_query, file_data)

            # Récupérer l'ID généré pour analysis_file_id
            analysis_file_id = cursor.lastrowid

            # Insertion dans la table FileScans pour chaque moteur de scan
            scans = data.get('scans', {})
            for engine_name, scan_info in scans.items():
                insert_scan_query = """
                INSERT INTO FileScans 
                (engine_name_files, detected, result, update_date, version, analysis_file_id) 
                VALUES (%s, %s, %s, %s, %s, %s)
                """
                scan_data = (
                    engine_name,
                    scan_info.get('detected'),
                    scan_info.get('result'),
                    scan_info.get('update'),
                    scan_info.get('version'),
                    analysis_file_id
                )
                cursor.execute(insert_scan_query, scan_data)

            # Valider les changements dans la base de données
            connection.commit()
            print("Données insérées avec succès")

        else:
            print(f"Erreur lors de la requête. Code d'erreur : {response.status_code}")

    except mysql.connector.Error as err:
        print(f"Erreur MySQL : {err}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()

# Exécution du script
if __name__ == "__main__":
    # Remplacez ceci par votre clé API VirusTotal
    api_key = 'votre_api_key'
    
    # Demander à l'utilisateur d'entrer le type de requête et la valeur à analyser
    query_type = 'file'
    query_value = input("Entrez l'ID du fichier à analyser : ")
    
    # Exemple de contenu de fichier analysé
    content_file = query_value

    # Appeler la fonction pour interroger l'API et insérer les données dans la base de données
    query_and_insert_virustotal(api_key, query_type, query_value, content_file)
