#!/bin/bash


OUTPUT_PATH="/Users/noahheraud/cyber/python/Scapy/analyse_pcap/malicious_traffic.pcap"

INTERFACE=$(ifconfig | grep -o '^[a-z0-9]*' | grep -v '^$' | head -1)

if ! nc -z localhost 8080 &>/dev/null; then
    echo "ATTENTION: Aucun serveur web détecté sur localhost:8080"
    echo "Démarrage d'un serveur web de test sur le port 8080..."
        python3 -m http.server 8080 &
    WEB_SERVER_PID=$!
    sleep 2
fi

sudo tcpdump -i $INTERFACE -w "$OUTPUT_PATH" 'port 8080' &
TCPDUMP_PID=$!


sleep 3


curl "http://localhost:8080/search?query=<script>alert('XSS')</script>" || echo "Échec de la requête XSS"
curl "http://localhost:8080/login" -d "username=admin&password=' OR '1'='1" || echo "Échec de la requête SQLi"
curl "http://localhost:8080/upload.php" -d "data=<?php eval(base64_decode('BASE64CODE')); ?>" || echo "Échec de la requête PHP"
curl "http://localhost:8080/register" -d "username=user&password=123" || echo "Échec de la requête weak password"


sleep 5


echo "Arrêt de tcpdump..."
sudo kill -2 $TCPDUMP_PID
sleep 2

# Arrêter le serveur web si nous l'avons démarré
if [ -n "$WEB_SERVER_PID" ]; then
    kill $WEB_SERVER_PID
fi

# Vérifier si le fichier a été créé
if [ -f "$OUTPUT_PATH" ]; then
    FILESIZE=$(stat -f%z "$OUTPUT_PATH")
else
    echo "ERREUR: Le fichier PCAP n'a pas été créé"
fi