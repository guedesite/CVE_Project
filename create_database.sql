DROP DATABASE IF EXISTS cve_test;
CREATE DATABASE IF NOT EXISTS cve_test;

USE cve_test;

CREATE TABLE `cve` (
  `id` integer PRIMARY KEY AUTO_INCREMENT,
  `cve_id` varchar(255),
  `source_id` integer,
  `published_date` datetime,
  `last_modified_date` datetime,
  `description` varchar(255),
  `cvss_v3_score` double,
  `cvss_v3_vector` varchar(255),
  `vendors` varchar(255),
  `products` varchar(255),
  `raw_data` JSON
);

CREATE TABLE `source` (
  `id` integer PRIMARY KEY AUTO_INCREMENT,
  `url` varchar(255)
);

ALTER TABLE `cve` ADD FOREIGN KEY (`source_id`) REFERENCES `source` (`id`);


INSERT INTO `source` (`id`, `url`) VALUES
(1, 'https://www.opencve.io'),
(2, 'https://cvedetails.com'),
(3, 'https://nvd.nist.gov');


INSERT INTO `cve` (`id`, `cve_id`, `source_id`, `published_date`, `last_modified_date`, `description`, `cvss_v3_score`, `cvss_v3_vector`, `vendors`, `products`, `raw_data`) VALUES
(
  101,
  'CVE-2024-0001',
  1,
  '2024-01-15 10:00:00',
  '2024-01-20 12:30:00',
  'Une vulnérabilité critique dans le composant X permettant une exécution de code à distance.',
  9.8,
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  '["VendorA", "VendorB"]',
  '["ProductX v1.0", "ProductY v2.2"]',
  '{"id": "CVE-2024-0001", "summary": "Critical RCE in X component.", "details": "Further details here...", "cvss_metrics": {"v31": {"score": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}}'
),
(
  102,
  'CVE-2024-0002',
  2,
  '2024-02-10 08:00:00',
  '2024-02-11 15:00:00',
  'Faille de type Cross-Site Scripting (XSS) dans le module de recherche.',
  6.1,
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
  '["VendorC"]',
  '["WebAppSuite v3.0"]',
  '{"cve_id": "CVE-2024-0002", "description_text": "XSS in search module.", "affected_products": [{"vendor": "VendorC", "product": "WebAppSuite", "versions": ["3.0", "3.1-beta"]}]}'
),
(
  103,
  'CVE-2023-1234',
  1,
  '2023-11-01 14:00:00',
  '2024-01-05 09:45:00',
  'Vulnérabilité de déni de service dans le service Z.',
  7.5,
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
  '["VendorA"]',
  '["ServiceZ Core"]',
  '{"id": "CVE-2023-1234", "summary": "DoS in Z service.", "references": ["url1", "url2"]}'
),
(
  104,
  'CVE-2024-0003',
  3,
  '2024-03-01 11:00:00',
  '2024-03-02 16:20:00',
  'Escalade de privilèges possible via une mauvaise configuration des permissions.',
  7.8,
  'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
  '["OSProvider"]',
  '["KernelXYZ"]',
  '{"cve": {"CVE_data_meta": {"ID": "CVE-2024-0003"}, "description": {"description_data": [{"lang": "en", "value": "Privilege escalation due to misconfigured permissions."}]}, "impact": {"baseMetricV3": {"cvssV3": {"baseScore": 7.8}}}}}'
),
(
  105,
  'CVE-2024-0004',
  2,
  '2024-03-15 09:00:00',
  '2024-03-15 09:00:00',
  'Divulgation d''informations sensibles dans l''API de gestion.',
  5.3,
  'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
  '["VendorD"]',
  '["ManagementAPI v1.5"]',
  '{"cve_id": "CVE-2024-0004", "description_text": "Sensitive information disclosure in management API.", "cvss_score_v3": 5.3}'
);