# Analyse automatisée des vulnérabilités - Projet 3ICS
 
![Cybersecurity](https://img.shields.io/badge/Security-CTI-red?style=for-the-badge&logo=target)
 
# Sommaire
 
- [Description](#description)
- [Technologies Utilisées](#technologies-utilisées)
- [Diagramme de cas d'utilisation](#diagramme-de-cas-dutilisation)
- [Objectifs du projet](#objectifs-du-projet)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Dépendances](#dépendances)
- [Livrables](#livrables)
 
 
## Description
 
[cite_start]Dans un contexte de multiplication des cybermenaces, les entreprises doivent être capables d'identifier rapidement les vulnérabilités présentes dans leur système d'information[cite: 3]. [cite_start]La détection et la corrélation manuelle entre les actifs d'un réseau (matériels, logiciels, services) et les bases de connaissance de menaces (CTI : Cyber Threat Intelligence) constituent une tâche complexe et chronophage[cite: 4].
 
[cite_start]Ce projet vise à développer un outil capable de scanner automatiquement une infrastructure réseau afin d'identifier les matériels, logiciels et services présents[cite: 5]. [cite_start]L'application fait ensuite correspondre ces éléments avec les bases de données CTI (telles que CVE, CWE, et CPE) pour détecter les vulnérabilités connues affectant les composants identifiés[cite: 5].
 
 
## Technologies Utilisées
 
| **Nom** | **Description** |
| ------- | ------------- |
| ![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) | [cite_start]Langage principal pour le pipeline de traitement[cite: 16]. |
| ![NVD](https://img.shields.io/badge/NVD-CTI_Data-orange?style=for-the-badge) | [cite_start]Base de données pour l'extraction des CVE et CPE[cite: 15]. |
| ![Scan](https://img.shields.io/badge/Network_Scanner-Survey-blue?style=for-the-badge) | [cite_start]Outil de cartographie automatique des actifs[cite: 14]. |
| ![Git](https://img.shields.io/badge/git-%23F05033.svg?style=for-the-badge&logo=git&logoColor=white) | [cite_start]Contrôle de version pour le code source. |
 
 
## Diagramme de cas d'utilisation
 

 
Le système permet de :
1. [cite_start]Cartographier l'infrastructure (machines, ports, services)[cite: 7].
2. [cite_start]Collecter les informations de menaces (CVE, CWE, CPE).
3. [cite_start]Faire le matching entre actifs et vulnérabilités[cite: 9].
 
 
## Objectifs du projet
 
L'outil répond aux exigences suivantes :
* [cite_start]**Cartographie** : Identification des versions logicielles et matérielles[cite: 7].
* [cite_start]**Collecte CTI** : Interrogation d'OpenCTI, NVD et autres bases publiques[cite: 8, 15].
* [cite_start]**Matching** : Algorithme de corrélation entre les services détectés et les failles connues[cite: 9, 16].
* [cite_start]**Reporting (Optionnel)** : Génération d'un rapport avec criticité et correctifs[cite: 10].
* [cite_start]**Visualisation (Optionnel)** : Représentation graphique du réseau et des risques[cite: 11].
 
 
## Prérequis
 
Pour exécuter ce projet, vous devez avoir :
* Un environnement Python installé.
* [cite_start]Un accès internet pour la synchronisation avec les bases CTI (NVD/OpenCTI)[cite: 15].
* [cite_start]Les privilèges suffisants pour effectuer des scans réseau sur la cible[cite: 14].
 
 
## Installation
 
Clonez le projet :
```bash
git clone [https://github.com/votre-user/Projet-3ICS-CTI.git](https://github.com/votre-user/Projet-3ICS-CTI.git)
