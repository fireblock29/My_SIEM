# Installation d’une VM Debian 13 (CLI) – netinst

Ce guide explique, en ligne de commande (mode texte), comment installer Debian 13 à partir de l’ISO netinst, jusqu’au premier login. Il convient à la plupart des hyperviseurs (VMware, VirtualBox, GNOME Boxes/Machines, KVM/QEMU, etc.). Nous supposons que vous avez déjà créé une VM et que vous la démarrez directement sur l’ISO.

ISO utilisée (amd64) :
- Lien officiel: https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.1.0-amd64-netinst.iso
- Fichier: debian-13.1.0-amd64-netinst.iso

## Prérequis rapides (recommandés)
- **Ressources VM**: 1+ vCPU, 2+ Go RAM, 10+ Go disque.
- **Réseau**: mode « Pont/Bridged » recommandé pour accéder à Kibana depuis votre PC. En NAT, prévoyez des redirections de ports (5601, 9200, 8080) si nécessaire.
- **Démarrage**: la VM doit booter sur l’ISO netinst.

## 1) Démarrage et menu initial
Au menu de démarrage Debian, choisissez:
- **Install** (pas « Graphical install »), pour une installation en mode texte (CLI).

Le programme d’installation charge les composants nécessaires et démarre l’assistant.

## 2) Langue, pays, clavier
- **Choose language**: Français (ou votre préférence).
- **Select your location**: votre pays.
- **Configure locales**: par défaut selon le choix précédent (ex: fr_FR.UTF-8).
- **Keymap**: choisissez votre disposition de clavier (ex: Français).

## 3) Configuration réseau
- **DHCP**: laissez faire si votre réseau fournit une IP automatiquement. 
- **Statique (optionnel)**: si vous devez fixer une IP, choisissez « Configure network manually » et saisissez:
  - Adresse IP, masque, passerelle, DNS.
- **Hostname**: par exemple `debian13`.
- **Domain name**: laissez vide ou saisissez votre domaine interne (optionnel).

## 4) Comptes et mots de passe
- **Mot de passe root**: définissez un mot de passe root (recommandé pour pouvoir utiliser `su` comme dans le README du projet).
- **Utilisateur standard**: entrez le nom complet, le login (ex: `student`) et un mot de passe.

Note: Si vous laissez le mot de passe root vide, l’utilisateur standard recevra sudo par défaut, mais la commande `su` ne sera pas utilisable. Le README du projet utilise `su`, donc il est préférable de définir un mot de passe root ici.

## 5) Horloge et fuseau horaire
- **Time zone**: choisissez votre fuseau (ex: `America/Toronto` ou `Europe/Paris`).

## 6) Partitionnement du disque
Choisissez l’une des options guidées:
- **Guided – use entire disk** (recommandé en labo) + **LVM** (facultatif mais pratique) 
  - Schéma simple « All files in one partition » convient très bien.
  - Confirmez l’écriture des changements sur le disque quand demandé.
  - Si vous n'avez pas d'autre OS à installer sur votre VM, à la question "Faut-il analyser d'autres supports d'installation ?", choisissez "Non".

Alternative: créez des partitions séparées (`/`, `swap`), uniquement si vous avez des besoins spécifiques.

## 7) Installation du système de base
L’installeur copie les fichiers et installe le système minimal.

## 8) Miroir Debian (apt)
- **Country of mirror**: choisissez votre pays.
- **Debian archive mirror**: `deb.debian.org` (par défaut, fiable et anycast).
- **HTTP proxy**: laissez vide sauf si votre réseau l’exige.

## 9) Popularity contest
- **Participate in package usage survey?** Répondez **Yes** ou **No** (au choix).

## 10) Sélection des logiciels
Pour une installation CLI légère:
- Décochez « Desktop environment » et « Gnome » (toutes interfaces graphiques).
- Cochez **SSH server** (optionnel mais utile) et **standard system utilities**.

Validez pour lancer l’installation des paquets sélectionnés.

## 11) Chargeur d’amorçage (GRUB)
- Choisissez **Yes** pour installer GRUB.
- Cible: le disque principal (ex: `/dev/sda` ou `/dev/vda`).

## 12) Fin de l’installation
- Terminez l’installateur, éjectez l’ISO si nécessaire.
- Laissez la VM redémarrer sur le nouveau système.

## 13) Premier démarrage et connexion
Connectez-vous en **root** (avec le mot de passe défini) ou avec l’utilisateur et passez root via `su`:
```bash
login: root
# ou
login: student
Password: ********
su
Password (root): ********
```

Mettez à jour le système:
```bash
apt update && apt upgrade -y
```

Vérifiez votre adresse IP (utile pour accéder à Kibana ensuite):
```bash
ip addr show
# ou
hostname -I
```

## Étapes suivantes (projet My_SIEM)
Suivez le `README.md` du projet pour:
- Cloner le dépôt, exécuter `install.sh`, redémarrer.
- Lancer `docker compose up -d`.
- Ouvrir Kibana: `http://VM_IP:5601`.

## Dépannage rapide (installation)
- **Pas de réseau (DHCP)**: vérifiez le mode réseau (bridged vs NAT), le DHCP de votre LAN, ou configurez une IP statique.
- **Miroir injoignable**: réessayez un autre miroir, vérifiez la passerelle/DNS.
- **GRUB non installé**: relancez l’installation de GRUB depuis le menu de secours, ou vérifiez la sélection du disque bootable.
- **Firmware manquant**: Debian 13 intègre les firmwares non-free dans les ISO récentes, mais si un firmware est demandé, acceptez l’installation si proposé.

Bonne installation !
