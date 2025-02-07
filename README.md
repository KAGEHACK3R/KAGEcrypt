# KAGEcrypt

**KAGEcrypt** est un outil avancé de cryptage/décryptage de fichiers développé par **GUY KOUAKOU (KAGEH@CK3R)**.  
Ce projet met à disposition une solution sécurisée et ergonomique pour protéger vos données grâce aux dernières avancées en cryptographie.

## Caractéristiques

- **Double interface (GUI & CLI)**  
  - Interface graphique moderne basée sur Tkinter (avec support optionnel du glisser-déposer).
  - Interface en ligne de commande pour l'automatisation et l'intégration dans des scripts.

- **Sécurité avancée**  
  - **Authentification multifactorielle (MFA)** avec TOTP via `pyotp` (un secret MFA est généré et sauvegardé dans un fichier de configuration).
  - Choix entre deux algorithmes de chiffrement :  
    - **Fernet** (basé sur AES en mode CBC avec authentification)  
    - **AES-GCM** (mode GCM pour une sécurité renforcée)
  - **Dérivation de clé sécurisée** via Argon2 (grâce à `argon2-cffi`).

- **Fonctionnalités supplémentaires**  
  - Compression optionnelle des fichiers avant chiffrement (et décompression lors du décryptage).
  - Traitement parallèle des répertoires avec reporting de progression et possibilité d'annuler l'opération.
  - Logging détaillé dans un fichier (`kagecrypt.log`) et affichage en temps réel dans l'interface graphique.
  - Stubs prévus pour la vérification de mises à jour et la synchronisation cloud (à implémenter ultérieurement).

## Prérequis

- **Python 3.6** ou une version ultérieure.
- Les bibliothèques Python suivantes :
  - `cryptography`
  - `argon2-cffi`
  - `pyotp`
  - `tkinterdnd2` (optionnel – pour activer le glisser-déposer dans l'interface GUI)
  - **Tkinter** (fourni par défaut avec Python sur la plupart des distributions)

## Installation

### 1. Cloner le dépôt

Ouvrez votre terminal et exécutez :

```bash
git clone https://github.com/votre-utilisateur/KAGEcrypt.git
cd KAGEcrypt

2. Créer et activer un environnement virtuel (optionnel mais recommandé)
Sur Linux/macOS :

bash
Copier
python3 -m venv venv
source venv/bin/activate

Sur Windows :

bash
Copier
python -m venv venv
venv\Scripts\activate
3. Installer les dépendances
Installez les packages requis avec :

bash
Copier
pip install -r requirements.txt
Exemple de contenu pour requirements.txt :

nginx
Copier
cryptography
argon2-cffi
pyotp
tkinterdnd2  # Optionnel

4. Utilisation
Interface Graphique (GUI)
Pour lancer l'application en mode graphique, exécutez :

bash
Copier
python kagecrypt.py
Interface en Ligne de Commande (CLI)
Pour lancer le chiffrement ou le déchiffrement via la CLI, utilisez la syntaxe suivante :
Chiffrement :

bash
Copier
python kagecrypt.py encrypt <chemin> --password "<votre_mot_de_passe>" --mfa <code_MFA> [--compress] [--algo fernet|aesgcm]
Exemple :

bash
Copier
python kagecrypt.py encrypt /chemin/vers/fichier.pdf --password "MaSuperClef" --mfa 123456 --compress --algo fernet
Déchiffrement :

bash
Copier
python kagecrypt.py decrypt <chemin> --password "<votre_mot_de_passe>" --mfa <code_MFA>
Packaging en Exécutable
Pour créer un exécutable autonome (par exemple avec PyInstaller) :

Installez PyInstaller :
pip install pyinstaller
Générez l'exécutable :

bash
Copier
pyinstaller --onefile --windowed kagecrypt.py
L'exécutable sera disponible dans le dossier dist.

Configuration
Lors du premier lancement, un fichier de configuration kagecrypt_config.json sera créé.
Ce fichier contient notamment le secret MFA nécessaire pour la vérification TOTP. Conservez-le précieusement car il est indispensable pour déverrouiller l'accès.

Sécurité
Choisissez un mot de passe robuste pour protéger vos données.
Le secret MFA est stocké localement. Veillez à la sécurité de votre appareil.
Mettez régulièrement à jour les bibliothèques utilisées pour bénéficier des derniers correctifs de sécurité.
Contribuer
Les contributions sont les bienvenues !
Si vous souhaitez apporter des améliorations ou signaler un problème, veuillez ouvrir une issue ou soumettre une pull request sur GitHub.

Licence
Ce projet est sous licence MIT. Consultez le fichier LICENSE pour plus d'informations.

Contact
Pour toute question ou suggestion, contactez :
GUY KOUAKOU (KAGEH@CK3R)
[gkouakou174@gmail.com]



