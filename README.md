# WIRE_ENGINE

**WIRE_ENGINE** est une interface avancée d'analyse de trafic réseau en temps réel, inspirée de Wireshark, développée en Python avec Tkinter.

Cette application permet de capturer, visualiser, analyser et historiser le trafic réseau qui traverse votre routeur, votre passerelle ou votre carte réseau locale.

---

## Table des matières

1. Présentation
2. Fonctionnalités
3. Installation
4. Lancement
5. Interface
6. Protocoles supportés
7. Capture de paquets
8. Résolution DNS
9. Scan du réseau local
10. Appareils connectés
11. Statistiques et graphiques
12. Base de données SQLite
13. Filtres BPF
14. Export et import PCAP
15. Configuration
16. Architecture du code
17. Classes principales
18. Gestion des erreurs
19. Sécurité et conformité
20. Développement futur
21. FAQ
22. Licence
23. Contact

---

## 1. Présentation

WIRE_ENGINE a été conçu pour offrir une expérience proche de Wireshark mais dans une interface légère, personnalisable et entièrement en noir et blanc.

L'application capture les paquets en temps réel grâce à Scapy, les analyse, les affiche dans une table interactive et fournit une explication simple de chaque protocole détecté.

---

## 2. Fonctionnalités

- Capture temps réel via Scapy
- Interface graphique Tkinter noir et blanc
- Table des paquets avec coloration par protocole
- Panneau d'explication détaillée
- Liste des appareils connectés au réseau local
- Résolution DNS et reverse DNS
- Géolocalisation IP (via GeoIP2)
- Statistiques en temps réel
- Graphique de répartition des protocoles
- Historisation SQLite
- Filtres BPF
- Export / import PCAP
- Scan réseau automatique et manuel
- Configuration persistante JSON
- Multithreading pour éviter le blocage de l'interface

---

## 3. Installation

### Prérequis

- Python 3.8 ou supérieur
- Droits administrateur ou root pour la capture de paquets
- Nmap installé sur le système

### Installation des dépendances

```bash
pip install -r requirements.txt
```

### Sous Linux

```bash
sudo apt install nmap libpcap-dev
sudo python3 wire_engine.py
```

### Sous Windows

Installez Nmap depuis le site officiel, puis lancez Wire Engine avec des droits administrateur.

### Sous macOS

```bash
brew install nmap libpcap
sudo python3 wire_engine.py
```

---

## 4. Lancement

```bash
python wire_engine.py
```

La fenêtre principale s'ouvre avec le titre WIRE_ENGINE en plein écran.

---

## 5. Interface

L'interface est divisée en plusieurs zones :

- En-tête avec le titre et l'état de la capture
- Barre de contrôle : interface, filtre, boutons Démarrer/Arrêter/Scanner
- Table centrale des paquets capturés
- Panneau d'explication détaillée
- Panneau latéral des appareils connectés
- Panneau des statistiques
- Graphique des protocoles
- Pied de page avec le nombre de paquets

Le thème est noir et blanc avec des accents cyan pour une lisibilité optimale.

---

## 6. Protocoles supportés

WIRE_ENGINE reconnaît et colore les protocoles suivants :

- ARP
- ICMP
- TCP
- UDP
- DNS
- HTTP
- HTTPS
- SSH
- SMTP
- DHCP
- Autres

---

## 7. Capture de paquets

La capture utilise Scapy en mode promiscuous. Elle s'exécute dans un thread dédié pour ne pas bloquer l'interface.

L'utilisateur peut choisir l'interface réseau et appliquer un filtre BPF.

---

## 8. Résolution DNS

WIRE_ENGINE extrait les requêtes DNS des paquets pour afficher les noms de domaine consultés.

Il effectue également du reverse DNS pour obtenir les noms d'hôte associés aux adresses IP.

---

## 9. Scan du réseau local

Un scanner réseau basé sur Nmap découvre les appareils connectés.

Le scan peut être lancé manuellement ou automatiquement à intervalle régulier.

---

## 10. Appareils connectés

Le panneau Appareils affiche :

- Adresse IP
- Adresse MAC
- Fabricant
- Nom d'hôte
- Statut en ligne
- Date de première et dernière apparition

---

## 11. Statistiques et graphiques

Les statistiques incluent :

- Nombre total de paquets
- Répartition par protocole
- Top des adresses IP
- Top des domaines

Le graphique en barres est mis à jour automatiquement toutes les 500 ms.

---

## 12. Base de données SQLite

WIRE_ENGINE historise les paquets et les appareils dans une base SQLite locale.

Tables :

- packets : paquets capturés
- devices : appareils détectés
- stats : statistiques par protocole

---

## 13. Filtres BPF

Les filtres BPF permettent de restreindre la capture.

Exemples :

- tcp port 80
- udp
- host 192.168.1.1
- icmp
- port 443

---

## 14. Export et import PCAP

L'application permet d'importer des fichiers PCAP existants pour les analyser.

L'export PCAP est prévu pour une version future.

---

## 15. Configuration

Les paramètres sont stockés dans wire_engine.json.

Options disponibles :

- interface
- filter
- max_packets
- auto_scroll
- show_payload
- dark_mode
- language
- geoip_enabled
- scan_interval
- pcap_auto_save

---

## 16. Architecture du code

Le projet est organisé autour de plusieurs classes :

- Configuration : gestion des paramètres
- Database : persistance SQLite
- NetworkTools : outils réseau et scan
- PacketAnalyzer : analyse et explication des paquets
- CaptureEngine : moteur de capture Scapy
- WireEngineApp : interface Tkinter

---

## 17. Classes principales

### Configuration

Charge et sauvegarde les préférences utilisateur dans un fichier JSON.

### Database

Gère la base de données SQLite avec des connexions thread-local.

### NetworkTools

Fournit les fonctions de découverte réseau, résolution DNS et scan Nmap.

### PacketAnalyzer

Analyse chaque paquet Scapy et produit une description lisible.

### CaptureEngine

Encapsule le sniff Scapy dans un thread sécurisé.

### WireEngineApp

Construit l'interface graphique et orchestre les autres composants.

---

## 18. Gestion des erreurs

L'application capture les exceptions dans les threads pour éviter les plantages.

Les erreurs sont affichées dans la console et les boîtes de dialogue utilisateur.

---

## 19. Sécurité et conformité

WIRE_ENGINE doit être utilisé uniquement sur des réseaux dont vous êtes propriétaire ou pour lesquels vous avez une autorisation explicite.

La capture de paquets peut être soumise à des réglementations locales.

---

## 20. Développement futur

- Export complet en PCAP
- Géolocalisation sur carte
- Détection d'anomalies
- Alertes en temps réel
- Support IPv6 complet
- Profils de capture
- Mode ligne de commande

---

## 21. FAQ

### Pourquoi WIRE_ENGINE nécessite-t-il les droits administrateur ?

La capture de paquets en mode promiscuous nécessite des privilèges élevés.

### Puis-je utiliser WIRE_ENGINE sans Nmap ?

Le scan réseau nécessite Nmap, mais la capture de paquets fonctionne sans.

### Où sont stockées les données ?

Dans les fichiers wire_engine.db et wire_engine.json.

---

## 22. Guide du développeur

### Structure des fichiers

```
.
├── wire_engine.py       # Application principale
├── requirements.txt     # Dépendances Python
├── README.md            # Documentation
├── wire_engine.json     # Configuration utilisateur
├── wire_engine.db       # Base de données SQLite
├── pcaps/               # Fichiers PCAP sauvegardés
└── logs/                # Journaux d'exécution
```

### Conventions de code

- PEP 8
- Docstrings Google
- Nommage explicite en anglais pour les symboles
- Constantes en MAJUSCULES
- Classes en CamelCase
- Fonctions et variables en snake_case

### Ajouter un nouveau protocole

1. Ajouter la couleur dans `PROTOCOL_COLORS`.
2. Ajouter la logique de détection dans `PacketAnalyzer.analyze`.
3. Ajouter une explication dans `_explain_packet`.
4. Mettre à jour les statistiques si nécessaire.

### Ajouter une nouvelle colonne dans la table

1. Modifier `build_packet_tree`.
2. Modifier `add_packet_to_ui`.
3. Modifier le schéma SQLite dans `Database.init_db`.
4. Mettre à jour `insert_packet`.

---

## 23. Détails de l'analyse des paquets

### Couche 2 : Ethernet

Chaque paquet commence par une trame Ethernet contenant :

- Adresse MAC source
- Adresse MAC destination
- Type Ethernet (IPv4, IPv6, ARP, etc.)

### Couche 3 : IP

Le paquet IP contient :

- Adresse IP source
- Adresse IP destination
- Protocole de transport (TCP, UDP, ICMP)
- TTL (Time To Live)
- Taille du paquet

### Couche 4 : TCP/UDP

TCP fournit une connexion fiable avec :

- Ports source et destination
- Numéros de séquence
- Drapeaux SYN, ACK, FIN, RST, PSH, URG
- Fenêtre de réception

UDP est un protocole sans connexion avec :

- Ports source et destination
- Longueur du datagramme
- Somme de contrôle

### Couche 7 : Application

WIRE_ENGINE détecte les protocoles applicatifs courants en se basant sur les ports et le contenu.

---

## 24. Exemples de filtrage

| Filtre | Description |
|--------|-------------|
| `tcp` | Capture uniquement le TCP |
| `udp port 53` | Capture le DNS sur UDP |
| `icmp` | Capture les pings |
| `host 192.168.1.1` | Filtre sur une IP |
| `port 80` | Capture le trafic HTTP |
| `not arp` | Ignore le protocole ARP |
| `src host 10.0.0.5` | Filtre la source |
| `dst port 443` | Filtre le HTTPS destination |

---

## 25. Dépannage

### Erreur : permission denied

Lancez l'application avec `sudo` sous Linux ou en administrateur sous Windows.

### Erreur : interface non trouvée

Vérifiez que l'interface réseau est active et que Scapy la reconnaît.

### Erreur : Nmap not found

Installez Nmap et vérifiez qu'il est dans le PATH.

### Erreur : GeoIP2 database missing

Téléchargez la base GeoLite2-City et placez-la dans le répertoire de l'application.

### L'interface est lente

Réduisez `max_packets` ou appliquez un filtre plus restrictif.

---

## 26. Glossaire

| Terme | Définition |
|-------|------------|
| Paquet | Unité de données transmise sur le réseau |
| Trame | Unité de la couche liaison de données |
| BPF | Berkeley Packet Filter |
| Promiscuous | Mode d'écoute passif sur une interface |
| ARP | Address Resolution Protocol |
| DNS | Domain Name System |
| DHCP | Dynamic Host Configuration Protocol |
| TTL | Time To Live |
| MAC | Media Access Control |
| PCAP | Format de fichier de capture réseau |
| Nmap | Outil de scan réseau |
| Scapy | Bibliothèque Python de manipulation de paquets |

---

## 27. Performances

WIRE_ENGINE peut traiter plusieurs milliers de paquets par seconde selon le matériel.

Recommandations :

- Utilisez un filtre pour limiter la charge
- Limitez la taille de l'historique
- Désactivez la résolution DNS si elle n'est pas nécessaire
- Fermez les graphiques si la machine est peu puissante

---

## 28. Sécurité avancée

### Bonnes pratiques

- Ne capturez jamais sur un réseau public sans autorisation
- Protégez la base SQLite avec les permissions système
- Évitez de stocker des captures sensibles en clair
- Désactivez la résolution DNS si l'anonymat est important

### Anonymisation

Une future version pourra masquer les adresses IP et MAC dans les exports.

---

## 29. Intégrations possibles

- Suricata / Snort pour la détection d'intrusion
- ELK Stack pour le stockage et la visualisation
- Grafana pour les tableaux de bord
- VirusTotal pour l'analyse des domaines
- MISP pour le partage d'indicateurs

---

## 30. Cycle de vie d'un paquet capturé

1. Scapy reçoit le paquet depuis l'interface.
2. Le paquet est placé dans une file thread-safe.
3. `PacketAnalyzer` extrait les informations.
4. L'interface affiche le paquet dans la table.
5. La base de données SQLite stocke le paquet.
6. Les statistiques et graphiques sont mis à jour.
7. L'utilisateur peut cliquer pour voir l'explication.

---

## 31. Tests manuels recommandés

1. Lancer une capture sur `any`.
2. Générer du trafic avec `ping google.com`.
3. Naviguer sur un site web.
4. Vérifier que les paquets DNS apparaissent.
5. Scanner le réseau local.
6. Sélectionner un paquet et lire l'explication.
7. Importer un fichier PCAP.
8. Vérifier la persistance après redémarrage.

---

## 32. Historique des versions

### 1.0.0

- Première version fonctionnelle
- Capture, analyse, affichage, historisation
- Scan réseau et résolution DNS
- Interface noir et blanc

---

## 33. Remerciements

- Scapy
- Nmap
- Tkinter
- Matplotlib
- GeoIP2

---

## 34. Licence

MIT License - Voir le fichier source pour les détails.

---

## 35. Contact

Projet développé par CodePal.

