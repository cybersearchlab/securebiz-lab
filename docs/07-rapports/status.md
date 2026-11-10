# État d'avancement du projet

**Date de référence : 9 novembre 2026**

## Socle technique

  Élément                                  Statut
  ---------------------------------------- ------------
  Environnement Windows 11 / PowerShell    En place
  Docker Desktop et Docker Compose         En place
  API FastAPI / Uvicorn                    En place
  PostgreSQL 16                            En place
  Persistance Docker `securebiz_pgdata`    Configurée
  Connexion Psycopg                        Vérifiée
  `GET /`                                  Vérifiée
  `GET /health`                            Vérifiée
  Configuration centralisée                En place
  Structure initiale des packages Python   Créée

## Base de données et IAM

  Élément                                    Statut
  ------------------------------------------ ----------------------------------
  Rôle initial `securebiz_user`              Superuser selon `\du`
  Rôle limité `securebiz_app`                Créé, mot de passe défini
  Privilèges de `securebiz_app`              Non configurés
  Utilisation de `securebiz_app` par l'API   Non réalisée
  Modèle IAM multi-organisation              Conçu
  Migration SQL IAM                          Brouillon créé, non exécuté
  Politiques RLS                             Brouillon à revoir, non appliqué
  Authentification et autorisation API       Non implémentées

## Décisions d'architecture

-   Adopter un modèle multi-organisation.
-   Séparer les identités globales des appartenances aux organisations.
-   Autoriser des rôles différents pour un même utilisateur selon
    l'organisation.
-   Utiliser des contraintes composites pour préserver la cohérence
    tenant.
-   Prévoir RLS comme défense en profondeur.
-   Séparer le compte applicatif des comptes de maintenance.
-   Ne pas exposer les hashes de mots de passe dans les lectures
    utilisateur.

## Prochaines étapes recommandées

1.  Inspecter le fichier de migration IAM et corriger ses risques avant
    exécution.
2.  Définir le propriétaire des tables et le rôle de migration.
3.  Définir les privilèges minimaux du rôle `securebiz_app`.
4.  Tester une connexion SQL avec `securebiz_app`.
5.  Basculer l'API vers ce compte uniquement après validation des
    droits.
6.  Ajouter un suivi de migrations.
7.  Implémenter l'authentification, puis l'autorisation.
8.  Déployer le schéma IAM et tester l'isolation entre organisations.
9.  Ajouter des tests automatisés et une chaîne CI.

## Limites connues

Le projet est un prototype en cours. Aucun audit externe n'a été
réalisé. Aucune vulnérabilité d'un système tiers n'est affirmée. Les
fonctionnalités IAM et RLS ne doivent pas être présentées comme
opérationnelles tant qu'elles n'ont pas été déployées et testées.
