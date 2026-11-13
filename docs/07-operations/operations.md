# SecureBiz Lab — Manuel des opérations

**Chemin :** `docs/07-operations/operations.md`  
**Version de l'application :** 0.3.0  
**Environnement documenté :** développement local avec Docker Compose  
**Dernière vérification des procédures :** 13 novembre 2026

---

## 1. Objet et périmètre

Ce document décrit les opérations courantes nécessaires pour démarrer, arrêter, contrôler et tester SecureBiz Lab.

L'environnement documenté repose sur trois services Docker Compose :

| Service | Conteneur | Fonction |
|---|---|---|
| `api` | `securebiz-api` | API FastAPI |
| `db` | `securebiz-postgres` | PostgreSQL 16 avec pgsodium |
| `vault` | `securebiz-vault` | HashiCorp Vault Transit |

Les ports publiés sur la machine hôte sont limités à l'interface locale :

- API : `127.0.0.1:8000`
- PostgreSQL : `127.0.0.1:5433`
- Vault : `127.0.0.1:8200`

Les communications entre conteneurs utilisent le réseau Docker interne. L'API contacte PostgreSQL sur `db:5432` et Vault sur `vault:8200`.

Ce manuel décrit l'environnement de développement observé. Il ne constitue pas une procédure de déploiement en production.

## 2. Prérequis

Les outils suivants doivent être installés :

- Docker Engine ou Docker Desktop ;
- Docker Compose v2 ;
- Python 3.12 ou 3.13 pour les tests exécutés sur l'hôte ;
- Git ;
- un terminal PowerShell sous Windows ou un terminal compatible.

Versions constatées lors de la vérification :

- Docker Engine : `29.8.1` ;
- Docker Compose : `v5.5.1`.

Les commandes de ce document sont principalement écrites pour PowerShell depuis la racine du dépôt.

Vérifier les versions :

```powershell
docker version
docker compose version
python --version
```

## 3. Configuration de l'environnement

### 3.1 Fichier `.env`

Le fichier `.env` à la racine du dépôt fournit les variables utilisées par Docker Compose.

Les noms de variables référencés par `docker-compose.yml` sont :

```text
POSTGRES_DB
POSTGRES_USER
POSTGRES_PASSWORD
APP_DB_USER
APP_DB_PASSWORD
AUTH_DB_PASSWORD
VAULT_DEV_ROOT_TOKEN
```

Ne jamais versionner le fichier `.env` ni afficher ses valeurs dans les journaux, les captures d'écran ou les rapports.

Le fichier doit être cohérent avec la configuration des services. En particulier :

- `POSTGRES_DB`, `POSTGRES_USER` et `POSTGRES_PASSWORD` configurent l'initialisation PostgreSQL ;
- `APP_DB_USER` et `APP_DB_PASSWORD` sont utilisés par l'API ;
- `AUTH_DB_PASSWORD` configure le compte d'authentification dédié ;
- `VAULT_DEV_ROOT_TOKEN` doit correspondre au jeton de développement configuré dans le service Vault.

**Attention :** dans la configuration Compose actuellement inspectée, Vault utilise explicitement `dev-only-root-token`. La variable `VAULT_DEV_ROOT_TOKEN` injectée dans l'API doit donc avoir cette même valeur dans cet environnement de développement. Toute modification de cette configuration doit être coordonnée entre les deux services.

Ne pas réutiliser ces paramètres de développement en production.

### 3.2 Configuration de l'API

La classe `Settings` de `app/core/config.py` exige les variables suivantes :

```text
DB_HOST
DB_PORT
DB_NAME
DB_USER
DB_PASSWORD
AUTH_DB_USER
AUTH_DB_PASSWORD
```

Les valeurs par défaut observées sont :

| Paramètre | Valeur par défaut |
|---|---|
| `DB_PORT` | `5432` |
| `JWT_ISSUER` | `securebiz-api` |
| `JWT_AUDIENCE` | `securebiz-api` |
| `JWT_ACCESS_TTL_SECONDS` | `900` |
| `REFRESH_TTL_DAYS` | `7` |

Les durées JWT sont validées par la configuration Pydantic. L'algorithme JWT est fixé à HS256 dans le code et n'est pas configurable par variable d'environnement.

La clé secrète JWT est gérée par Vault, et non stockée dans le fichier de configuration Python.

L'application ne charge pas automatiquement un fichier `.env` depuis `app/core/config.py`. Dans Docker, les variables lui sont injectées par Compose.

### 3.3 Variables de test

`tests/conftest.py` définit des valeurs factices pour permettre l'import des modules pendant les tests host.

Ces valeurs comprennent notamment des variables `DB_*`, `AUTH_DB_*`, `VAULT_TOKEN` et `VAULT_ADDR`.

Elles ne sont pas des identifiants de connexion réels et ne doivent jamais être utilisées pour un déploiement.

## 4. Démarrage de l'environnement

Depuis la racine du dépôt :

```powershell
docker compose up -d --build
```

Cette commande construit les images nécessaires et démarre les trois services en arrière-plan.

Afficher l'état des conteneurs :

```powershell
docker compose ps
```

Afficher les journaux :

```powershell
docker compose logs --tail 100
```

Suivre les journaux d'un service :

```powershell
docker compose logs -f api
docker compose logs -f db
docker compose logs -f vault
```

Arrêter le suivi des journaux avec `Ctrl+C`. Cela n'arrête pas les conteneurs.

### 4.1 Ordre de disponibilité

Le service API dépend de l'état de santé de PostgreSQL et de Vault. Compose attend que leurs healthchecks soient satisfaits avant de démarrer l'API.

La disponibilité du conteneur API ne garantit toutefois pas que la clé Transit attendue est déjà provisionnée.

Le provisionnement Vault est une opération administrative distincte, décrite à la section 7.

## 5. Contrôle de santé de l'API

### 5.1 Endpoint racine

Depuis PowerShell :

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/"
```

La réponse attendue indique notamment :

- l'application `SecureBiz Lab` ;
- la version `0.3.0` ;
- le statut `running`.

### 5.2 Endpoint de santé

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health"
```

Cet endpoint vérifie que l'API peut établir une connexion à PostgreSQL et exécuter `SELECT 1`.

Une réponse saine indique :

```json
{
  "status": "healthy",
  "api": "available",
  "database": "connected"
}
```

Une réponse HTTP 503 signifie que le contrôle de santé n'a pas pu confirmer la disponibilité de la base de données.

Cet endpoint ne vérifie pas à lui seul le provisionnement de la clé Transit ni l'ensemble des permissions applicatives.

## 6. Arrêt et redémarrage

### 6.1 Arrêt normal

```powershell
docker compose stop
```

Les conteneurs sont arrêtés sans supprimer les conteneurs ni le volume PostgreSQL.

### 6.2 Redémarrage

```powershell
docker compose start
```

Après le redémarrage de Vault en mode développement, il faut vérifier son provisionnement.

### 6.3 Arrêt et suppression des conteneurs

```powershell
docker compose down
```

Cette commande supprime les conteneurs et le réseau Compose, mais conserve le volume nommé `securebiz_pgdata`.

**Ne pas ajouter `-v` à cette commande sans décision explicite :** `docker compose down -v` supprime également le volume PostgreSQL et peut entraîner la perte des données persistées.

## 7. Provisionnement administratif de Vault

### 7.1 Pourquoi cette opération est nécessaire

Vault est actuellement lancé en mode développement avec un stockage en mémoire (`-dev`).

Les clés Transit créées dans ce mode ne sont pas conservées après la perte de l'état mémoire, notamment lors de la recréation ou du redémarrage du service Vault.

Le script `scripts/init_vault.py` :

- active le moteur de secrets Transit si nécessaire ;
- crée la clé Ed25519 `securebiz-context` si elle n'existe pas.

Il est idempotent selon sa documentation : il peut être relancé lorsque le moteur et la clé existent déjà.

### 7.2 Quand exécuter le provisionnement

Exécuter le provisionnement :

- après le premier démarrage de l'environnement ;
- après toute recréation ou perte de l'état mémoire de Vault ;
- lorsque l'absence de la clé Transit est confirmée.

Ne pas exécuter ce script à chaque requête API.

### 7.3 Commande de provisionnement

Le script doit être lancé dans le conteneur API avec le répertoire de travail `/app` :

```powershell
docker exec -w /app securebiz-api env PYTHONPATH=/app python scripts/init_vault.py
```

Résultat attendu :

```text
Vault provisioning: OK
```

En cas d'échec, vérifier :

1. que le conteneur Vault est démarré ;
2. que `VAULT_ADDR` pointe vers `http://vault:8200` depuis le réseau Docker ;
3. que `VAULT_TOKEN` est présent dans le conteneur API ;
4. que le jeton correspond au jeton de développement Vault ;
5. que Vault est disponible et accepte le jeton.

Le script effectue des opérations administratives. Il doit être exécuté avec un jeton disposant des privilèges nécessaires. Le jeton root de développement ne doit jamais être utilisé comme modèle de gestion des privilèges en production.

## 8. Tests automatisés

Les tests sont séparés en deux catégories selon leurs dépendances.

### 8.1 Tests host

Les tests host sont conçus pour être exécutés depuis l'environnement Python local.

Ils utilisent les valeurs factices définies dans `tests/conftest.py` et des mocks pour isoler les composants nécessitant normalement des dépendances externes.

Commande complète utilisée par le workflow CI :

```powershell
python -m pytest `
  tests/test_dependencies_lifecycle.py `
  tests/test_jwt.py `
  tests/test_refresh.py `
  tests/test_auth_routes.py `
  tests/test_provision_user.py `
  -W error::DeprecationWarning `
  -v
```

Pour vérifier le nombre de tests collectés sans les exécuter :

```powershell
python -m pytest `
  tests/test_dependencies_lifecycle.py `
  tests/test_jwt.py `
  tests/test_refresh.py `
  tests/test_auth_routes.py `
  tests/test_provision_user.py `
  --collect-only -q
```

La collecte vérifiée le 13 novembre 2026 a retourné :

```text
108 tests collected
```

Ce nombre correspond aux cas de test collectés par Pytest, y compris les variantes produites par les tests paramétrés. Il ne constitue pas un résultat d'exécution.

### 8.2 Tests container

Les tests d'intégration nécessitent l'environnement Docker, PostgreSQL, Vault et le réseau interne des services.

Le workflow CI actuel ne les exécute pas.

Les fichiers concernés sont :

```text
tests/test_isolation.py
tests/test_isolation_users.py
tests/test_isolation_roles.py
tests/test_refresh_db.py
```

Depuis la racine du dépôt, avec les services démarrés :

```powershell
docker compose exec api python -m pytest `
  tests/test_isolation.py `
  tests/test_isolation_users.py `
  tests/test_isolation_roles.py `
  tests/test_refresh_db.py `
  -v
```

Ces tests doivent être exécutés dans un environnement de test contrôlé. Ils peuvent interagir avec PostgreSQL et Vault et ne doivent pas être lancés contre une base contenant des données réelles.

Le nombre de tests collectés pour ces fichiers doit être vérifié avec Pytest avant de publier un total global.

### 8.3 Compilation Python

Le contrôle de compilation utilisé par la CI est :

```powershell
python -m compileall -q app scripts tests
```

Un code de sortie nul indique que les fichiers Python ciblés ont pu être compilés.

## 9. Contrôles de sécurité

### 9.1 Bandit

Le workflow `security.yml` utilise Bandit pour analyser les répertoires `app` et `scripts`.

Commande :

```powershell
bandit -r app scripts -ll -iii
```

Le workflow installe :

```powershell
python -m pip install "bandit[toml]==1.9.4"
```

Bandit réalise une analyse statique ciblée sur les problèmes de sécurité détectables dans le code Python. Un résultat sans finding ne constitue pas une certification de sécurité.

### 9.2 Audit des dépendances

Le workflow utilise `pip-audit` sur `requirements.txt`.

Installation :

```powershell
python -m pip install "pip-audit==2.10.1"
```

Exécution :

```powershell
pip-audit -r requirements.txt
```

Ce contrôle recherche les vulnérabilités connues associées aux dépendances déclarées.

Il ne remplace ni une analyse de configuration, ni une revue de code, ni un test d'intrusion.

## 10. Workflows GitHub Actions

Deux workflows sont présents dans `.github/workflows/`.

### 10.1 `ci.yml`

Le workflow CI est déclenché sur :

- push vers `main` ;
- pull request vers `main` ;
- lancement manuel (`workflow_dispatch`).

Il exécute, sur Python 3.12 et Python 3.13 :

1. l'installation des dépendances ;
2. la compilation de `app`, `scripts` et `tests` ;
3. les 108 tests host ;
4. le traitement des avertissements `DeprecationWarning` comme erreurs.

Les tests container ne sont pas exécutés par ce workflow.

### 10.2 `security.yml`

Le workflow de sécurité est déclenché sur les mêmes événements.

Il comprend deux jobs :

- analyse statique avec Bandit ;
- audit des dépendances avec pip-audit.

### 10.3 Interprétation des résultats

Un workflow présent dans le dépôt ne signifie pas nécessairement qu'il a été exécuté avec succès.

Pour déclarer une vérification validée, consulter son exécution réelle dans GitHub Actions et vérifier le résultat de chacun des jobs.

Les tests container, Trivy et les contrôles DAST ne doivent pas être déclarés comme intégrés ou validés sur la seule base de ces deux fichiers.

## 11. Vérification globale de l'état

Le script `scripts/state_check.py` regroupe des contrôles sur PostgreSQL, Vault, les permissions et certains éléments du modèle de sécurité.

Commande :

```powershell
docker compose exec api python scripts/state_check.py
```

Le script contrôle notamment :

- les variables d'environnement Vault ;
- la présence de tables et de fonctions attendues ;
- la correspondance entre la clé publique Transit et celle enregistrée dans PostgreSQL ;
- les données de test ;
- l'état des refresh tokens ;
- les permissions d'exécution de `get_user_status` ;
- le rôle `securebiz_provisioner` ;
- la capacité de signature Transit ;
- le cycle d'installation et de récupération du contexte.

### 11.1 Identifiants administratifs PostgreSQL

Certains contrôles nécessitent `DB_ADMIN_USER` et `DB_ADMIN_PASSWORD`.

Si ces variables ne sont pas présentes dans le conteneur API, les contrôles administratifs concernés sont marqués `SKIP`. Un résultat global sans échec peut donc rester partiel.

Le script ne doit pas être considéré comme entièrement concluant lorsque des contrôles importants ont été ignorés.

### 11.2 Effets et précautions

Ce script n'est pas strictement sans effet :

- les lectures PostgreSQL produisent des requêtes de consultation ;
- `check_vault_sign()` effectue une opération de signature Transit via HTTP POST, susceptible de générer des événements d'audit Vault ;
- `check_full_flow()` installe temporairement un contexte dans une transaction PostgreSQL, puis effectue un `ROLLBACK` ;
- le test de signature ne doit pas être confondu avec une simple lecture de l'état de Vault.

La transaction de `check_full_flow()` ne doit pas laisser de modification persistante lorsque le rollback fonctionne correctement.

Le script compare la clé publique présente dans Vault à celle enregistrée dans PostgreSQL. En cas de divergence, il signale un avertissement. Il ne doit pas synchroniser automatiquement les clés : une divergence peut signaler une perte ou une recréation de l'état Vault et nécessite une investigation.

Le script utilise une validation stricte de l'autorité Vault interne `vault:8200`. Il est prévu pour le réseau Docker documenté ici.

## 12. Diagnostic et dépannage

### 12.1 L'API ne démarre pas

Consulter :

```powershell
docker compose logs --tail 100 api
```

Vérifier :

- les variables `DB_*` et `AUTH_DB_*` ;
- la présence des variables obligatoires ;
- la disponibilité de PostgreSQL ;
- les erreurs de validation Pydantic ;
- les erreurs d'import Python.

### 12.2 PostgreSQL n'est pas healthy

Consulter :

```powershell
docker compose logs --tail 100 db
docker compose ps -a
```

Vérifier :

- les variables `POSTGRES_DB`, `POSTGRES_USER` et `POSTGRES_PASSWORD` ;
- l'état du volume `securebiz_pgdata` ;
- l'exécution des scripts d'initialisation SQL ;
- la disponibilité du port interne 5432.

Les scripts du répertoire `database/init` sont montés dans `/docker-entrypoint-initdb.d`. Leur exécution dépend du mécanisme d'initialisation de l'image PostgreSQL, notamment de l'état du répertoire de données. Une modification de ces scripts ne signifie pas qu'ils seront rejoués automatiquement sur un volume déjà initialisé.

### 12.3 Vault est indisponible ou la clé manque

Consulter :

```powershell
docker compose logs --tail 100 vault
docker compose ps -a
```

Si Vault a perdu son état mémoire, exécuter à nouveau le provisionnement administratif décrit à la section 7.

Ne pas modifier automatiquement la clé publique stockée dans PostgreSQL pour masquer une divergence.

### 12.4 L'endpoint `/health` retourne HTTP 503

Consulter les journaux API et PostgreSQL :

```powershell
docker compose logs --tail 100 api
docker compose logs --tail 100 db
```

L'endpoint vérifie l'accès à la base de données. Un problème Vault ou une clé absente peut affecter d'autres fonctionnalités sans nécessairement expliquer directement ce statut HTTP 503.

### 12.5 Les tests host échouent à l'import

Vérifier que :

- l'environnement virtuel est actif ;
- les dépendances de `requirements.txt` sont installées ;
- `tests/conftest.py` est présent ;
- les variables factices de test sont définies avant l'import des modules applicatifs.

Réinstaller les dépendances si nécessaire :

```powershell
python -m pip install -r requirements.txt
```

### 12.6 Les tests container échouent

Vérifier que les trois services sont démarrés et que PostgreSQL et Vault sont disponibles :

```powershell
docker compose ps
docker compose logs --tail 100 api
docker compose logs --tail 100 db
docker compose logs --tail 100 vault
```

Vérifier également que les données de test attendues existent et que les tests sont exécutés dans le conteneur API, avec les dépendances et le réseau interne nécessaires.

## 13. Limites et exigences avant une mise en production

La configuration actuelle est une configuration de laboratoire et ne doit pas être exposée comme environnement de production.

Points majeurs à traiter avant toute mise en production :

1. Remplacer Vault en mode développement par un déploiement persistant, sécurisé et correctement initialisé.
2. Remplacer le jeton root de développement par une politique de moindre privilège et des jetons dédiés.
3. Mettre en place une gestion sécurisée des secrets, leur rotation et leur révocation.
4. Configurer TLS pour les communications qui sortent du périmètre local ou du réseau interne de confiance.
5. Désactiver les paramètres de diagnostic propres au développement, notamment `DEBUG_HEADERS`.
6. Vérifier les règles réseau, les permissions PostgreSQL, les rôles et les politiques RLS.
7. Mettre en place sauvegardes, restauration testée et supervision.
8. Définir les procédures de rotation des clés et de récupération après incident.
9. Intégrer et valider les contrôles complémentaires requis, notamment les analyses d'images de conteneurs et les tests dynamiques si le périmètre l'exige.
10. Vérifier les workflows CI et sécurité sur des exécutions réelles avant de considérer les contrôles comme validés.

Les ports publiés sur `127.0.0.1` réduisent l'exposition réseau de l'environnement local, mais ne remplacent pas une architecture de sécurité de production.

## 14. Références du dépôt

| Fichier | Rôle |
|---|---|
| `docker-compose.yml` | Définition des services et du réseau |
| `Dockerfile` | Construction de l'image API |
| `postgres/Dockerfile` | Construction de l'image PostgreSQL |
| `app/core/config.py` | Validation de la configuration API |
| `app/main.py` | Initialisation FastAPI et endpoint de santé |
| `scripts/init_vault.py` | Provisionnement administratif Vault |
| `scripts/state_check.py` | Contrôles de cohérence et d'état |
| `tests/conftest.py` | Préparation de l'environnement de tests host |
| `.github/workflows/ci.yml` | Tests et compilation automatisés |
| `.github/workflows/security.yml` | Bandit et pip-audit |
| `requirements.txt` | Dépendances Python |

---

**Fin du document — SecureBiz Lab / Opérations**