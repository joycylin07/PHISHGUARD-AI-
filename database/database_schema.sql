CREATE DATABASE IF NOT EXISTS phishguard_db;

USE phishguard_db;

CREATE TABLE scan_history (
    scan_id INT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    overall_risk DECIMAL(5,2) NOT NULL,
    risk_level VARCHAR(20) NOT NULL,
    phishing_probability DECIMAL(5,2) NOT NULL,
    source VARCHAR(50),
    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
