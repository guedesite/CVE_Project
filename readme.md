# CVE Scanner

## Requirements

- Python 3.10
- Node.js 22

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