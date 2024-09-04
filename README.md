
# Threat Intelligence Dashboard for Ooredoo Tunisia

## Description

Ce projet consiste à créer un tableau de bord de **Threat Intelligence** en utilisant **Grafana** et **MySQL**. Il collecte, analyse et visualise les données provenant de plusieurs sources, notamment **VirusTotal**, **AbuseIPDB**, et **AlienVault OTX**. L'objectif est de fournir à Ooredoo une vue d'ensemble des menaces de sécurité à travers des fichiers malveillants, des adresses IP suspectes, et des indicateurs de compromission (IoC).


## Prérequis

- Python 3.x
- MySQL
- Grafana
- Clés API pour VirusTotal, AbuseIPDB, et AlienVault OTX
- Git

## Installation

1. **Cloner le dépôt Git** :
   ```bash
   git clone https://github.com/votre_nom/threat-intelligence-dashboard.git
   cd threat-intelligence-dashboard
   ```

2. **Installer les dépendances Python** :
   Assurez-vous d'avoir installé `pip` et installez les dépendances en exécutant la commande suivante :
   ```bash
   pip install -r requirements.txt
   ```

3. **Configurer MySQL** :
   - Créez la base de données MySQL en utilisant le fichier `scripts/database_setup.sql` :
     ```bash
     mysql -u root -p < scripts/database_setup.sql
     ```

4. **Configurer Grafana** :
   - Connectez Grafana à la base de données MySQL en utilisant les informations de configuration fournies dans `grafana_dashboards/grafana_setup.md`.

## Structure des fichiers

```
├── README.md
├── LICENSE
├── requirements.txt
├── scripts/
│   ├── virus_total_file.py
│   ├── virus_total_url.py
│   ├── virus_total_ip.py
│   ├── abuseipdb.py
│   ├── alienvault.py
│   └── ooredoo_db.sql
└── requirements.txt
├── grafana_dashboards/
│   ├── dashboard.json
│   └── grafana_setup.md
├── data/
│   ├── example_virustotal_ip.json
│   ├── example_virustotal_file.json
│   └── example_virustotal_url.json
└── .gitignore
```

### Explication des fichiers :
- **README.md** : Ce fichier, avec des instructions sur l'utilisation du projet.
- **requirements.txt** : Liste des dépendances Python requises.
- **scripts/** : Contient les scripts pour interagir avec les APIs, insérer des données dans MySQL.
- **grafana_dashboards/** : Contient la configuration des dashboards Grafana.
- **data/** : Contient des exemples de fichiers JSON pour les tests de l'API virustotal.

## Configuration

1. **Configurer les clés API et MySQL** :
   - Modifiez le fichier `config/config.yaml` pour ajouter vos clés API et informations de connexion MySQL :
     ```yaml
     mysql:
       host: localhost
       user: root
       password: your_password
       database: threat_intelligence
     apis:
       virus_total_key: your_virus_total_api_key
       abuseipdb_key: your_abuseipdb_api_key
       alienvault_key: your_alienvault_api_key
     ```

2. **Lancer les scripts pour insérer les données** :
   - Utilisez les scripts dans le dossier `scripts/` pour récupérer et insérer les données issues des APIs dans la base de données MySQL- NB: il faut modifier le mot de passer de la base de données MySQL et la valeur de l'API_KEY dans chacun de ces fichiers python 

**`virus_total_file.py`** : 
  - **Description** : Ce script interagit avec l'API de VirusTotal pour interroger des fichiers. Il récupère des informations telles que les résultats des analyses, les moteurs d'analyse et les fichiers détectés, puis insère ces données dans la base de données MySQL. Il prend comme entrée un fichier.
  - **Usage** :
    ```bash
    python scripts/virus_total_file.py
    ```
  
- **`virus_total_url.py`** : 
  - **Description** : Ce script interagit avec l'API de VirusTotal pour analyser des URLs. Il envoie des requêtes pour obtenir des rapports d'analyse sur des URLs suspectes, puis insère les résultats dans les tables correspondantes dans la base de données. Il prend comme entrée un url.
  - **Usage** :
    ```bash
    python scripts/virus_total_url.py
    ```

- **`virus_total_ip.py`** : 
  - **Description** : Ce script interroge l'API VirusTotal pour analyser des adresses IP suspectes. Il récupère les résultats d'analyse des adresses IP et les insère dans les tables `IpAnalysis` et `IpCommunicatingSamples`. Il prend comme entrée une adresse IP.
  - **Usage** :
    ```bash
    python scripts/virus_total_ip.py
    ```

- **`abuseipdb.py`** : 
  - **Description** : Ce script interagit avec l'API AbuseIPDB pour vérifier des plages d'adresses IP sur la base de signalements d'abus. Les données sont ensuite insérées dans les tables `AbuseIpReport` et `ReportedIps` de la base de données. Il prend comme entrée une adresse réseau.
  - **Usage** :
    ```bash
    python scripts/abuseipdb.py
    ```

- **`alienvault.py`** : 
  - **Description** : Ce script interagit avec l'API d'AlienVault OTX pour obtenir des informations sur les pulses de sécurité, les IoCs (Indicators of Compromise), et les techniques d'attaque associées. Les informations récupérées sont insérées dans les tables `Pulses`, `PulseIndicators`, et `AttackTechniques`. Il fournit dans les pulses qui sont ajoutées ou modifiés le jour qui précède celui de l'exécution du code.
  - **Usage** :
    ```bash
    python scripts/alienvault.py


- **`ooredoo_db.sql`** : 
  - **Description** : Ce script permet de construire la base de données threat_intellegence en l'exécutant dans  MySQL Workbench 8.0 CE.
 - **explication** : 
# Base de données `threat_intelligence`

Cette base de données stocke des informations sur les menaces de sécurité (threat intelligence) collectées pour l'opérateur Ooredoo Tunisie. Elle contient plusieurs tables interconnectées pour gérer les analyses de fichiers, d'URL, d'adresses IP, ainsi que les techniques d'attaque et les rapports d'abus.

## Tables

 1. `FilesAnalysis`
Stocke les informations sur les fichiers analysés.

- **`analysis_file_id`** : (INT, PRIMARY KEY, AUTO_INCREMENT) Identifiant unique pour chaque fichier analysé.
- **`md5_hash`** : (VARCHAR(255)) Hash MD5 du fichier analysé.
- **`permalink`** : (VARCHAR(255)) Lien permanent vers le rapport de l'analyse du fichier.
- **`positives`** : (INT) Nombre de moteurs d'analyse ayant détecté le fichier comme malveillant.
- **`resource`** : (VARCHAR(255)) Ressource associée au fichier analysé.
- **`response_code`** : (INT) Code de réponse de l'analyse.
- **`analysis_file_date`** : (DATETIME) Date et heure de l'analyse du fichier.
- **`content_file`** : (TEXT) Contenu du fichier analysé.

 2. `FileScans`
Stocke les résultats des analyses de fichiers effectuées par différents moteurs d'analyse.

- **`engine_name_files`** : (VARCHAR(255), PRIMARY KEY) Nom du moteur d'analyse.
- **`detected`** : (BOOLEAN) Indique si une menace a été détectée.
- **`result`** : (VARCHAR(255)) Résultat de l'analyse du moteur.
- **`update_date`** : (DATETIME) Date de la dernière mise à jour des signatures du moteur.
- **`version`** : (VARCHAR(50)) Version du moteur d'analyse.
- **`analysis_file_id`** : (INT, PRIMARY KEY, FOREIGN KEY) Identifiant de l'analyse de fichier, lié à la table `FilesAnalysis`.

 3. `UrlsAnalysis`
Stocke les informations sur les URL analysées.

- **`analysis_url_id`** : (INT, PRIMARY KEY, AUTO_INCREMENT) Identifiant unique pour chaque URL analysée.
- **`url`** : (VARCHAR(255)) URL analysée.
- **`filescan_id`** : (VARCHAR(255)) Identifiant de l'analyse du fichier associé à l'URL.
- **`permalink`** : (VARCHAR(255)) Lien permanent vers le rapport d'analyse de l'URL.
- **`positives`** : (INT) Nombre de moteurs ayant détecté l'URL comme malveillante.
- **`resource`** : (VARCHAR(255)) Ressource associée à l'URL analysée.
- **`response_code`** : (INT) Code de réponse de l'analyse de l'URL.
- **`analysis_url_date`** : (DATETIME) Date et heure de l'analyse de l'URL.

 4. `UrlScans`
Stocke les résultats des analyses d'URLs par différents moteurs.

- **`engine_url_files`** : (VARCHAR(255), PRIMARY KEY) Nom du moteur d'analyse ayant scanné l'URL.
- **`detected`** : (BOOLEAN) Indique si une menace a été détectée.
- **`result`** : (VARCHAR(255)) Résultat de l'analyse.
- **`analysis_url_id`** : (INT, PRIMARY KEY, FOREIGN KEY) Référence à l'analyse d'URL associée dans la table `UrlsAnalysis`.

 5. `IpAnalysis`
Stocke les informations sur les adresses IP analysées.

- **`ip_address`** : (VARCHAR(45), PRIMARY KEY) Adresse IP analysée.
- **`asn_owner`** : (VARCHAR(255)) Propriétaire du système autonome (ASN) auquel appartient l'adresse IP.
- **`asn`** : (INT) Numéro ASN associé à l'adresse IP.
- **`country`** : (VARCHAR(50)) Pays associé à l'adresse IP.

 6. `IpCommunicatingSamples`
Stocke les échantillons détectés qui ont communiqué avec les adresses IP analysées.

- **`sample_id`** : (INT, PRIMARY KEY, AUTO_INCREMENT) Identifiant unique pour chaque échantillon détecté.
- **`ip_address`** : (VARCHAR(45), FOREIGN KEY) Référence à l'adresse IP associée dans la table `IpAnalysis`.
- **`sha256_hash`** : (VARCHAR(255)) Hash SHA-256 de l'échantillon détecté.
- **`positives`** : (INT) Nombre de moteurs ayant détecté l'échantillon comme malveillant.
- **`total`** : (INT) Nombre total de moteurs ayant analysé l'échantillon.
- **`date_detected`** : (DATETIME) Date à laquelle l'échantillon a été détecté.

 7. `AbuseIpReport`
Stocke les rapports d'abus relatifs aux plages d'adresses IP.

- **`report_id`** : (INT, PRIMARY KEY, AUTO_INCREMENT) Identifiant unique pour chaque rapport d'abus.
- **`network_address`** : (VARCHAR(255)) Adresse réseau associée au rapport.
- **`netmask`** : (VARCHAR(255)) Masque de sous-réseau de la plage IP.
- **`min_address`** : (VARCHAR(45)) Première adresse IP de la plage.
- **`max_address`** : (VARCHAR(45)) Dernière adresse IP de la plage.
- **`num_possible_hosts`** : (INT) Nombre d'hôtes possibles dans la plage d'IP.
- **`address_space_desc`** : (VARCHAR(255)) Description de l'espace d'adresses IP.

 8. `ReportedIps`
Stocke les adresses IP spécifiques signalées pour des activités malveillantes.

- **`ip_address`** : (VARCHAR(45), PRIMARY KEY) Adresse IP signalée pour abus.
- **`report_id`** : (INT, FOREIGN KEY) Référence au rapport d'abus associé dans la table `AbuseIpReport`.
- **`num_reports`** : (INT) Nombre de rapports d'abus concernant cette adresse IP.
- **`most_recent_report`** : (DATETIME) Date du rapport d'abus le plus récent.
- **`abuse_confidence_score`** : (INT) Score indiquant la fiabilité des rapports d'abus.
- **`country_code`** : (VARCHAR(10)) Code du pays où est située l'adresse IP.

 9. `Pulses`
Stocke les informations sur les pulses de sécurité.

- **`pulse_key`** : (VARCHAR(255), PRIMARY KEY) Identifiant unique de la pulse.
- **`name`** : (VARCHAR(255)) Nom de la pulse.
- **`description`** : (TEXT) Description détaillée de la menace ou de l'attaque.
- **`author_name`** : (VARCHAR(255)) Nom de l'auteur ayant créé la pulse.
- **`created`** : (DATETIME) Date de création de la pulse.
- **`modified`** : (DATETIME) Date de la dernière modification de la pulse.
- **`tlp`** : (VARCHAR(50)) Niveau de partage selon le protocole TLP.
- **`adversary`** : (VARCHAR(255)) Nom de l'adversaire ou du groupe responsable de la menace.

 10. `PulseIndicators`
Stocke les indicateurs de compromission (IoC) associés aux pulses.

- **`indicator_id`** : (INT, PRIMARY KEY, AUTO_INCREMENT) Identifiant unique pour chaque IoC.
- **`pulse_key`** : (VARCHAR(255), FOREIGN KEY) Référence à la pulse associée dans la table `Pulses`.
- **`indicator`** : (VARCHAR(255)) Indicateur de compromission (par exemple, adresse IP, URL).
- **`type`** : (VARCHAR(50)) Type de l'indicateur (par exemple, IP, domaine).
- **`created`** : (DATETIME) Date de création de l'indicateur.
- **`is_active`** : (BOOLEAN) Indique si l'indicateur est actuellement actif.
- **`role`** : (VARCHAR(255)) Rôle ou fonction de l'indicateur dans l'attaque.

 11. `AttackTechniques`
Stocke les techniques d'attaque observées pour chaque pulse.

- **`technique_code`** : (VARCHAR(50), PRIMARY KEY) Code unique pour chaque technique d'attaque.
- **`pulse_key`** : (VARCHAR(255), PRIMARY KEY, FOREIGN KEY) Référence à la pulse associée dans la table `Pulses`.



## Utilisation

1. **Initialisation de la base de données** :
   - Exécutez le fichier `ooredoo_db.sql` pour créer toutes les tables nécessaires dans MySQL Workbench 8.0 CE.
   - Lancez les scripts d'API pour insérer les données dans la base de données.

2. **Lancer Grafana** :
   - Configurez Grafana pour se connecter à MySQL, puis importez le fichier `grafana_dashboards/dashboard.json` pour visualiser les données.

