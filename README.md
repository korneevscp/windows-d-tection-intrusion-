# Système de Détection d'Intrusion (IDS) pour Windows

## Description

Ce programme est un Système de Détection d'Intrusion (IDS) développé en C pour Windows. Il surveille en temps réel votre ordinateur pour détecter des activités suspectes, des malwares, des connexions réseau non autorisées et des comportements anormaux.

Le système fonctionne en surveillance continue et vous alerte via des popups Windows dès qu'une menace potentielle est détectée.

---

## Fonctionnalités Principales

### 1. Détection de Processus Malveillants

Le système détecte automatiquement les processus suspects par leur nom :

- Outils de piratage : netcat, mimikatz, psexec, procdump
- Keyloggers : logiciels d'enregistrement de frappe
- Backdoors : payload.exe, shell.exe, beacon
- Ransomwares : cryptolocker et variantes
- Exploits : metasploit, meterpreter

**Actions effectuées :**
- Scanne tous les processus en cours d'exécution
- Compare avec une liste de noms malveillants connus
- Affiche une popup critique avec les détails (nom, PID, utilisateur)
- Enregistre l'alerte dans un fichier log

---

### 2. Détection de Rootkits

Les rootkits sont des malwares qui se déguisent en processus système Windows légitimes.

**Détection :**
- Processus système (svchost.exe, lsass.exe, csrss.exe, winlogon.exe) s'exécutant depuis des emplacements suspects
- Les vrais processus système doivent être dans C:\Windows\System32\
- Si un "svchost.exe" tourne depuis C:\Users\, c'est un rootkit potentiel

**Exemple d'alerte :**
```
=== ALERTE ROOTKIT POSSIBLE ===

Processus système suspect: svchost.exe
PID: 1234
Emplacement anormal: C:\Users\John\Desktop\svchost.exe

ATTENTION: Possible infection rootkit !
```

---

### 3. Surveillance des Ports Réseau

Le système surveille les ports suspects souvent utilisés par les pirates :

| Port  | Utilisation courante          |
|-------|-------------------------------|
| 4444  | Metasploit (backdoor)         |
| 5555  | Android Debug Bridge          |
| 6666  | IRC Botnet                    |
| 31337 | Port "Elite" Hacker           |
| 1337  | Backdoor classique            |
| 12345 | NetBus (trojan)               |
| 54321 | Back Orifice (trojan)         |

**Actions :**
- Teste si ces ports sont en écoute sur votre machine
- Alerte popup si un port suspect est ouvert
- Indication qu'un backdoor ou malware pourrait être actif

---

### 4. Surveillance des Ressources Système

Le système monitore en permanence :

#### Mémoire RAM
- Vérifie l'utilisation de la mémoire
- Alerte si > 90% (fuite mémoire ou malware possible)
- Causes possibles : cryptominers, ransomwares

#### Espace Disque
- Surveille le disque C:\
- Alerte si > 95%
- Cause possible : ransomware cryptant/dupliquant des fichiers

**Exemple d'alerte :**
```
=== ALERTE MEMOIRE ===

Utilisation mémoire critique: 95%

Causes possibles:
- Fuite mémoire (memory leak)
- Malware en exécution
- Processus suspect

Vérifiez les processus actifs !
```

---

### 5. Vérification de Windows Defender

Le système vérifie que Windows Defender (l'antivirus intégré) est bien actif.

**Importance :**
- De nombreux malwares désactivent l'antivirus en premier
- Si Defender est éteint sans votre action = infection possible

**Alerte si désactivé :**
```
=== ALERTE SECURITE ===

Windows Defender est DESACTIVE !

Risque:
- Système non protégé
- Possible malware

Action: Réactiver immédiatement !
```

---

### 6. Détection de Nouveaux Processus

Le système crée une baseline (référence) au démarrage :
- Liste tous les processus en cours
- À chaque scan, compare avec la baseline
- Notification si un nouveau processus apparaît

**Utile pour détecter :**
- Applications qui démarrent automatiquement
- Processus lancés à distance
- Malwares qui s'activent après un délai

---

### 7. Journalisation (Logging)

Toutes les alertes sont enregistrées dans :
```
C:\IDS\alerts.log
```

**Format du log :**
```
========================================
[2025-10-22 14:35:42]
=== ALERTE MALWARE DETECTE ===

Processus: mimikatz.exe
PID: 5678
Utilisateur: DESKTOP-ABC\John

ACTION RECOMMANDEE:
Terminer ce processus immédiatement !
========================================
```

**Avantages :**
- Historique complet des menaces
- Analyse post-incident
- Preuve en cas d'enquête
- Identification des patterns d'attaque

---

## Installation et Utilisation

### Prérequis

- Windows (7, 8, 10, 11)
- CodeBlocks avec MinGW (compilateur C)
- Droits Administrateur (obligatoire pour accéder aux infos système)

### Compilation

1. Ouvrez CodeBlocks
2. Créez un nouveau projet : File → New → Project → Console Application (C)
3. Copiez le code source dans main.c
4. Configurez les bibliothèques :
   - Project → Build options → Linker settings
   - Ajoutez : ws2_32, psapi, advapi32
5. Compilez avec F9

### Exécution

1. Clic droit sur l'exécutable généré
2. Sélectionnez "Exécuter en tant qu'administrateur"
3. Le système démarre automatiquement la surveillance

### Interface Console

```
  ================================================
  ||                                            ||
  ||  SYSTEME DE DETECTION D'INTRUSION (IDS)   ||
  ||            Windows Edition                 ||
  ||                                            ||
  ||  Protection Active - Surveillance 24/7    ||
  ||                                            ||
  ================================================

[*] Initialisation du système de détection...
[*] Création de la baseline du système...
[+] Baseline créée: 87 processus enregistrés

[+] Surveillance continue activée
[+] Notifications popup activées
[+] Fichier log: C:\IDS\alerts.log
[+] Appuyez sur Ctrl+C pour arrêter

========================================
  SCAN #1 - 2025-10-22 14:30:15
========================================

[*] Analyse des processus en cours...
[+] Aucune activité suspecte détectée

[*] Surveillance des connexions réseau...
[+] Vérification des ports terminée

[*] Surveillance des ressources système...
[*] Utilisation mémoire: 45%
[*] Utilisation disque C: 67%

[*] Vérification des services critiques...
[+] Windows Defender: ACTIF
[+] Vérification des services terminée

[*] Prochain scan dans 60 secondes...
[*] Surveillance active...
```

---

## Types d'Alertes

### Alertes Critiques (Rouges)

**MALWARE DÉTECTÉ**
- Processus malveillant identifié
- Action : Terminer immédiatement

**ALERTE ROOTKIT**
- Processus système dans un emplacement suspect
- Action : Scanner avec antivirus, restaurer système

**DEFENDER DÉSACTIVÉ**
- Antivirus éteint
- Action : Réactiver et scanner

### Alertes d'Avertissement (Jaunes)

**PORT SUSPECT**
- Port de backdoor en écoute
- Action : Identifier le processus responsable

**MÉMOIRE/DISQUE CRITIQUE**
- Ressources épuisées
- Action : Vérifier les processus gourmands

### Alertes d'Information (Bleues)

**NOUVELLE CONNEXION**
- Connexion réseau établie
- Information : Pour votre connaissance

**NOUVEAU PROCESSUS**
- Application démarrée
- Information : Surveillance normale

---

## Fonctionnement Technique

### Architecture du Système

```
┌─────────────────────────────────────┐
│   Interface Utilisateur (Console)   │
│   + Popups Windows                  │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   Moteur de Détection Principal     │
│                                      │
│  ┌────────────────────────────────┐ │
│  │ Module Processus               │ │
│  │ - Scan processus               │ │
│  │ - Détection malware            │ │
│  │ - Détection rootkit            │ │
│  └────────────────────────────────┘ │
│                                      │
│  ┌────────────────────────────────┐ │
│  │ Module Réseau                  │ │
│  │ - Scan ports                   │ │
│  │ - Détection backdoors          │ │
│  └────────────────────────────────┘ │
│                                      │
│  ┌────────────────────────────────┐ │
│  │ Module Système                 │ │
│  │ - Surveillance RAM/Disque      │ │
│  │ - Vérification services        │ │
│  └────────────────────────────────┘ │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│   APIs Windows                      │
│   - CreateToolhelp32Snapshot        │
│   - GetModuleFileNameEx             │
│   - OpenProcess                     │
│   - socket/bind                     │
│   - GlobalMemoryStatusEx            │
│   - OpenSCManager                   │
└─────────────────────────────────────┘
```

### Cycle de Surveillance

1. Démarrage : Création de la baseline (état normal du système)
2. Scan Continu : Toutes les 60 secondes
3. Comparaison : État actuel vs baseline
4. Détection : Identification des anomalies
5. Alertes : Popups + Log fichier
6. Boucle : Retour à l'étape 2

---

## Sécurité et Limitations

### Ce que le système PEUT détecter

- Malwares avec noms connus
- Rootkits basiques (processus déguisés)
- Ports backdoor classiques
- Désactivation de l'antivirus
- Anomalies de ressources

### Ce que le système NE PEUT PAS détecter

- Malwares polymorphes (qui changent de nom/forme)
- Rootkits avancés (niveau kernel)
- Zero-days (vulnérabilités inconnues)
- Attaques réseau externes (le système ne voit que votre PC)
- Malwares fileless (en mémoire uniquement)

### Recommandations de Sécurité

Ce système est un complément à votre sécurité, PAS un remplacement :

1. Gardez Windows Defender activé
2. Mettez à jour Windows régulièrement
3. Utilisez un firewall
4. Ne désactivez jamais votre antivirus
5. Complétez avec un antivirus tiers si possible (Malwarebytes, Bitdefender)

---

## Guide de Réponse aux Incidents

### Si "MALWARE DÉTECTÉ" apparaît :

1. NE FERMEZ PAS la popup immédiatement
2. Notez le nom du processus et le PID
3. Ouvrez le Gestionnaire des tâches (Ctrl+Shift+Esc)
4. Trouvez le processus par son PID
5. Terminez le processus (clic droit → Terminer)
6. Scannez avec Windows Defender (scan complet)
7. Vérifiez le fichier log : C:\IDS\alerts.log

### Si "ALERTE ROOTKIT" apparaît :

1. TRÈS SÉRIEUX - Ne redémarrez pas encore
2. Notez l'emplacement du fichier
3. Scannez avec Malwarebytes (téléchargez si nécessaire)
4. Considérez une restauration système
5. Changez vos mots de passe (depuis un autre appareil)

### Si "PORT SUSPECT" apparaît :

1. Identifiez quel processus utilise le port
2. Dans le Gestionnaire des tâches → onglet Détails
3. Recherchez le processus en ligne (est-il légitime ?)
4. Bloquez le port dans le Pare-feu Windows si nécessaire

---

## Personnalisation

### Modifier la fréquence des scans

Dans le code, ligne 71 :
```c
Sleep(60000); // 60 secondes = 1 minute
```

Changez en :
```c
Sleep(300000); // 300 secondes = 5 minutes
Sleep(30000);  // 30 secondes
Sleep(10000);  // 10 secondes
```

### Ajouter des processus suspects

Dans la fonction isProcessSuspicious(), ligne 401 :
```c
const char* suspiciousNames[] = {
    "nc.exe", "netcat", "ncat.exe",
    // AJOUTEZ VOS NOMS ICI
    "monmalware.exe",
    "suspect.exe"
};
```

### Ajouter des ports suspects

Dans la fonction monitorConnections(), ligne 263 :
```c
int suspiciousPorts[] = {4444, 5555, 6666, 31337, 1337, 12345, 54321};
```

Ajoutez vos ports :
```c
int suspiciousPorts[] = {4444, 5555, 6666, 8888, 9999};
```

---

## Dépannage

### Problèmes de Compilation

- Vérifiez que les bibliothèques sont bien liées : ws2_32, psapi, advapi32
- Assurez-vous d'avoir MinGW installé avec CodeBlocks
- Compilez en mode "Release" pour de meilleures performances

### Le programme ne démarre pas

- Exécutez en tant qu'administrateur (obligatoire)
- Vérifiez que le pare-feu ne bloque pas le programme
- Créez le dossier C:\IDS manuellement si nécessaire

### Fausses Alertes

- Certains logiciels légitimes peuvent déclencher des alertes
- Vérifiez toujours en ligne si un processus est légitime
- Ajoutez des exceptions dans le code si nécessaire

---

## Licence et Avertissement

### Usage

Ce programme est fourni à des fins éducatives et de sécurité personnelle uniquement.

### Avertissement Légal

- N'utilisez ce programme que sur VOS PROPRES ordinateurs
- L'utilisation sur des systèmes tiers sans autorisation est ILLÉGALE
- L'auteur n'est pas responsable d'une utilisation abusive


---

## Korneevscp

Programme développé en C pour Windows. Pour toute question ou amélioration, consultez la documentation ou le code source.
