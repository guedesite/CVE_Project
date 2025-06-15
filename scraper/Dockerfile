FROM python:3.9-slim

# Dépendances système
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    curl \
    gnupg \
    chromium \
    chromium-driver \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Définir le répertoire de travail
WORKDIR /app

# Copier les fichiers nécessaires
COPY requirements.txt ./requirements.txt
COPY script ./script

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Définir les variables d’environnement nécessaires pour Selenium
ENV PATH="/usr/lib/chromium:/usr/lib/chromium/chromedriver:$PATH"
ENV CHROME_BIN="/usr/bin/chromium"
ENV CHROMEDRIVER_PATH="/usr/bin/chromedriver"
