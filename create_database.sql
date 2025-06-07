DROP DATABASE IF EXISTS cve_project;
CREATE DATABASE cve_project;
USE cve_project;

-- Table des sources
CREATE TABLE source (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(255) NOT NULL,
  url VARCHAR(255)
);

-- Table des CVE
CREATE TABLE cve (
  id INT PRIMARY KEY AUTO_INCREMENT,
  cve_id VARCHAR(255) UNIQUE NOT NULL,
  source_id INT,
  published_date DATETIME,
  last_modified_date DATETIME,
  description TEXT,
  cvss_v3_score DOUBLE,
  cvss_v3_vector VARCHAR(255),
  raw_data JSON,
  FOREIGN KEY (source_id) REFERENCES source(id)
);

-- Table des produits affectés
CREATE TABLE product (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(255),
  version VARCHAR(255),
  vendor VARCHAR(255)
);

-- Liaison CVE ↔ produits
CREATE TABLE cve_product (
  cve_id INT,
  product_id INT,
  FOREIGN KEY (cve_id) REFERENCES cve(id),
  FOREIGN KEY (product_id) REFERENCES product(id)
);

-- Remplissage de la base de données refactorisée avec des exemples réels

-- Sources disponibles
INSERT INTO source (id, name, url) VALUES
(1, 'OpenCVE', 'https://www.opencve.io'),
(2, 'NVD', 'https://nvd.nist.gov');

-- CVE
INSERT INTO cve (id, cve_id, source_id, published_date, last_modified_date, description, cvss_v3_score, cvss_v3_vector, raw_data) VALUES
(1, 'CVE-2024-3094', 2, '2024-04-01 10:00:00', '2024-04-01 15:00:00', 'RCE in XZ Utils affecting SSH server communication.', 9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', '{"example":true}'),
(2, 'CVE-2024-22245', 2, '2024-03-10 08:30:00', '2024-03-12 10:00:00', 'VMware Workstation Local Privilege Escalation.', 7.8, 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', '{"example":true}'),
(3, 'CVE-2023-4863', 2, '2023-09-11 12:00:00', '2023-09-11 12:00:00', 'Heap buffer overflow in WebP in Google Chrome.', 8.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', '{"example":true}');

-- Produits
INSERT INTO product (id, name, version, vendor) VALUES
(1, 'xz-utils', '5.6.0', 'XZ Project'),
(2, 'vmware-workstation', '17.5.0', 'VMware'),
(3, 'libwebp', '1.3.1', 'Google'),
(4, 'google-chrome', '116.0', 'Google');

-- Liens CVE/Produits
INSERT INTO cve_product (cve_id, product_id) VALUES
(1, 1),
(2, 2),
(3, 3),
(3, 4);
