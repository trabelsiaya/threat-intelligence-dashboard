CREATE DATABASE threat_intelligence;
USE threat_intelligence;
CREATE TABLE FilesAnalysis (
    analysis_file_id INT AUTO_INCREMENT PRIMARY KEY,
    md5_hash VARCHAR(255),
    permalink VARCHAR(255),
    positives INT,
    resource VARCHAR(255),
    response_code INT,
    analysis_file_date DATETIME,
    content_file TEXT
);

CREATE TABLE FileScans (
    engine_name_files VARCHAR(255),
    detected BOOLEAN,
    result VARCHAR(255),
    update_date DATETIME,
    version VARCHAR(50),
    analysis_file_id INT,
    PRIMARY KEY (engine_name_files ,analysis_file_id),
    FOREIGN KEY (analysis_file_id) REFERENCES FilesAnalysis(analysis_file_id)
);

CREATE TABLE UrlsAnalysis (
    analysis_url_id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(255),
    filescan_id VARCHAR(255),
    permalink VARCHAR(255),
    positives INT,
    resource VARCHAR(255),
    response_code INT,
    analysis_url_date DATETIME
);

CREATE TABLE UrlScans (
    engine_url_files VARCHAR(255),
    detected BOOLEAN,
    result VARCHAR(255),
    analysis_url_id INT,
    PRIMARY KEY (engine_url_files, analysis_url_id),
    FOREIGN KEY (analysis_url_id) REFERENCES UrlsAnalysis(analysis_url_id)
);

CREATE TABLE IpAnalysis (
    ip_address VARCHAR(45) PRIMARY KEY,
    asn_owner VARCHAR(255),
    asn INT,
    country VARCHAR(50)
);

CREATE TABLE IpCommunicatingSamples (
    sample_id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45),
    sha256_hash VARCHAR(255),
    positives INT,
    total INT,
    date_detected DATETIME,
    FOREIGN KEY (ip_address) REFERENCES IpAnalysis(ip_address)
);

CREATE TABLE AbuseIpReport (
    report_id INT AUTO_INCREMENT PRIMARY KEY,
    network_address VARCHAR(255),
    netmask VARCHAR(255),
    min_address VARCHAR(45),
    max_address VARCHAR(45),
    num_possible_hosts INT,
    address_space_desc VARCHAR(255)
);

CREATE TABLE ReportedIps (
    ip_address VARCHAR(45),
    report_id INT,
    num_reports INT,
    most_recent_report DATETIME,
    abuse_confidence_score INT,
    country_code VARCHAR(10),
    PRIMARY KEY(ip_address),
    FOREIGN KEY (report_id) REFERENCES AbuseIpReport(report_id)
);

CREATE TABLE Pulses (
    pulse_key VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    author_name VARCHAR(255),
    created DATETIME,
    modified DATETIME,
    tlp VARCHAR(50),
    adversary VARCHAR(255)
);

CREATE TABLE PulseIndicators (
    indicator_id INT AUTO_INCREMENT PRIMARY KEY,
    pulse_key VARCHAR(255),
    indicator VARCHAR(255),
    type VARCHAR(50),
    created DATETIME,
    is_active BOOLEAN,
    role VARCHAR(255),
    FOREIGN KEY (pulse_key) REFERENCES Pulses(pulse_key)
);

CREATE TABLE AttackTechniques (
    technique_code VARCHAR(50) ,
    pulse_key VARCHAR(255),
    PRIMARY KEY (technique_code ,pulse_key),
    FOREIGN KEY (pulse_key) REFERENCES Pulses(pulse_key)
);







