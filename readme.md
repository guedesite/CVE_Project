# CVE Scanner

This project uses a **lightweight, local data lake architecture** to collect and query CVE (Common Vulnerabilities and Exposures) data efficiently without requiring any cloud infrastructure.

---

## Data Lake Architecture

###  Storage Layer – Apache Parquet

* All CVE records are stored in a **single Parquet file** (`cve_data.parquet`), which resides locally.
* **Parquet** is a columnar storage format optimized for analytical workloads. It offers:

  * Efficient compression and low storage footprint
  * Fast read performance for queries over large datasets
  * Native support for schema evolution and type consistency

### Query Engine – DuckDB

* The API and web interface query the Parquet data using **DuckDB**:

  * An in-process SQL engine (like SQLite, but for analytics)
  * Can read Parquet files directly without loading the full dataset into memory
  * Supports SQL filters by product, version, vendor, severity, etc.

### ️ Ingestion – Python + Cron

* A scheduled **Python script** fetches the latest CVEs daily from trusted sources (e.g. NVD API).
* The script:

  * Normalizes and merges data into the Parquet file
  * Ensures no duplication using `cve_id` as a unique key
* It can be executed manually or automatically via `cron` or similar task scheduler.

###  Why this setup?

* **No external dependencies** (no Hadoop, no cloud storage)
* **Low cost** and easy to set up anywhere
* **Extensible**: new sources can be added by creating a parser that outputs a DataFrame with a consistent schema
* **Fast queries** with minimal memory usage thanks to Parquet + DuckDB

---

## Requirements

- Python 3.10
- Node.js 22


## Contributing

All CVE data from additional sources (APIs, scanners, feeds, etc.) must be **normalized** into the same structure used in the main Parquet file (`cve_data.parquet`).

You can find an implementation in  **controller/fetch/data_services_nvd_nist_gov.py**

#### Required Columns:

| Column           | Type     | Description                                                                 |
|------------------|----------|-----------------------------------------------------------------------------|
| `cve_id`         | string   | Official CVE identifier (e.g., `CVE-2023-12345`)                          |
| `vendor`         | string   | Name of the vendor or creator of the affected technology                   |
| `product`        | string   | Name of the affected technology/library/application                        |
| `version`        | string   | Affected version (can be empty if unknown or multiple)                     |
| `description`    | string   | Short summary of the vulnerability                                          |
| `severity`       | string   | Severity level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), if available         |
| `cvss_score`     | float    | Numerical CVSS score (0.0 to 10.0), 0.0 if not available                 |
| `cvss_version`   | string   | CVSS version used for scoring (`2.0`, `3.0`, `3.1`, `4.0`)                |
| `published_date` | string   | CVE publication date in YYYY-MM-DD format                                  |

#### Example:

```json
{
  "cve_id": "CVE-2024-56789",
  "vendor": "apache",
  "product": "httpd",
  "version": "2.4.57",
  "description": "Buffer overflow in mod_ssl...",
  "severity": "HIGH"
}
```


## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/guedesite/P1000-PTZ
cd P1000-PTZ
```

### 2. Setup Python Environment

Create and activate a virtual environment:

```bash
python -m venv env
```

**Windows:**
```bash
env/Scripts/activate
```

**Linux/macOS:**
```bash
source env/bin/activate
```

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4. Setup Web Interface

Navigate to the web directory and install Node.js dependencies:

```bash
cd web
npm install
```

Build the React application:

```bash
npm run build
cd ..
```


## Usage

### Start the Application

```bash
python app.py
```