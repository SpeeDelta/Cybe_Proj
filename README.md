# Analyse automatisée des vulnérabilités d'une infrastructure réseau à partir de la Cyber Threat Intelligence (CTI) 
![Security Badge](https://img.shields.io/badge/Security-CTI-red?style=for-the-badge&logo=target)

# Sommaire

- [Description](#description)
- [Technologies Utilisées](#technologies-utilisées)
- [Objectifs](#diagramme-de-cas-dutilisation)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Dépendances](#dépendances)
- [Livrables](#livrables)

## Description

Dans un contexte de multiplication des cybermenaces, les entreprises doivent être capables d'identifier rapidement les vulnérabilités de leur système d'information. Cependant, la détection et la corrélation manuelle entre les actifs réseau (matériels, logiciels, services) et les bases de connaissance de menaces (CTI) constituent une tâche complexe et chronophage.

Ce projet vise à développer un outil capable de scanner automatiquement une infrastructure réseau afin d'identifier les composants présents, puis de faire correspondre ces éléments avec les bases de données CTI (telles que CVE, CWE, et CPE) pour détecter les vulnérabilités connues.

## Technologies Utilisées

| **Nom** | **Description** |
| ------- | ------------- |
| ![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) | Langage utilisé pour la conception de l'algorithme et du pipeline[cite: 16]. |
| ![Network Scan](https://img.shields.io/badge/Scan-Nmap_/_Tools-blue?style=for-the-badge) | Utilisation d'un outil de scan réseau pour la cartographie des actifs. |
| ![CTI Data](https://img.shields.io/badge/CTI-CVE_/_NVD-orange?style=for-the-badge) | Extraction des données depuis les bases publiques (OpenCTI, NVD, etc.). |
| ![Git](https://img.shields.io/badge/git-%23F05033.svg?style=for-the-badge&logo=git&logoColor=white) | Contrôle de version pour le code source du prototype. |

## Objectifs :
* **Cartographier automatiquement** l'infrastructure (machines, ports, services, versions logicielles).
* **Collecter des informations CTI** depuis des sources comme OpenCTI, CVE, CWE, CPE ou NVD.
* **Réaliser le matching** entre les composants détectés et les vulnérabilités connues.
* **Générer des rapports** de vulnérabilité présentant les risques et les correctifs recommandés (Optionnel).
* **Visualiser graphiquement** le réseau et les vulnérabilités associées (Optionnel).

## Prérequis

Pour exécuter ce projet, vous devez disposer de :
* Un environnement d'exécution pour le code source.
* Un outil de scan réseau installé et configuré.
* Une connexion internet pour l'extraction des données CTI depuis les bases publiques.

## Installation

```bash
git clone [https://github.com/votre-user/projet-3ics-cti.git](https://github.com/votre-user/projet-3ics-cti.git)
python -m venv env
source env/bin/activate
pip install --upgrade pip
pip install -r requirements

```

## Utilisation

```bash
scan_rzo [network/mask] [report_direcotry] # network et report_directory optionels
```

## Dépendances

L'application dépend directement de l'accessibilité des bases de données CTI publiques (NVD, OpenCTI, etc.) ainsi que du bon fonctionnement de l'outil de scan réseau intégré.

## Livrables

Les éléments suivants sont attendus pour ce projet:

**Code source** de l'outil ou du prototype développé.

**Rapport technique** détaillant la démarche, les choix techniques et les résultats.

**Démonstration** ou présentation du fonctionnement de la solution.



---

*Projet 3ICS - 2025-2026* 

