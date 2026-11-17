#!/usr/bin/env python3
"""
Seed IAM de démonstration pour SecureBiz-Lab.

Crée EXCLUSIVEMENT, dans une transaction unique :
  - 2 rôles métier non système : owner, member
  - les affectations de permissions de ces 2 rôles
  - 2 utilisateurs de démonstration
  - 2 memberships
  - 2 affectations de rôles aux memberships

Ne touche JAMAIS :
  - auth_private.credentials
  - aux utilisateurs / memberships / rôles existants
  - aux permissions existantes

Fail-closed : toute collision ou prérequis manquant => rollback intégral.

Sécurité :
  - mot de passe administratif saisi via getpass (masqué)
  - aucun secret affiché
  - aucun accès à auth_private

Usage :
  docker compose run --rm -it --entrypoint python api /app/scripts/seed_demo_iam.py
  (Cette commande n'est PAS exécutée par la création du fichier.)
"""

import getpass
import sys

import psycopg

# ---------------------------------------------------------------------------
# Paramètres fixes (validés par inspection)
# ---------------------------------------------------------------------------

DB_HOST = "db"
DB_PORT = 5432
DB_NAME = "securebiz"
DB_USER = "securebiz_user"

ORG_ID = "1a40e607-b991-4b06-ad1f-13106d65b12a"

DEMO_OWNER_EMAIL = "demo-owner@securebiz-lab.dev"
DEMO_MEMBER_EMAIL = "demo-member@securebiz-lab.dev"

OWNER_ROLE_NAME = "owner"
MEMBER_ROLE_NAME = "member"

OWNER_PERMISSIONS = [
    "permissions:read",
    "reports:create",
    "reports:read",
    "roles:create",
    "roles:delete",
    "roles:read",
    "roles:update",
    "users:deactivate",
    "users:invite",
    "users:read",
    "users:update",
]

MEMBER_PERMISSIONS = [
    "roles:read",
    "users:read",
]

REQUIRED_PERMISSIONS = sorted(set(OWNER_PERMISSIONS) | set(MEMBER_PERMISSIONS))


class SeedError(Exception):
    """Erreur fonctionnelle du seed (prérequis manquant ou collision)."""


# ---------------------------------------------------------------------------
# Contrôles préalables (tous en lecture, dans la transaction)
# ---------------------------------------------------------------------------

def check_organization_exists(cur) -> None:
    cur.execute("SELECT 1 FROM public.organizations WHERE id = %s", (ORG_ID,))
    if cur.fetchone() is None:
        raise SeedError(f"Organisation {ORG_ID} absente.")


def check_permissions_present(cur) -> None:
    cur.execute(
        "SELECT code FROM public.permissions WHERE code = ANY(%s)",
        (REQUIRED_PERMISSIONS,),
    )
    found = {row[0] for row in cur.fetchall()}
    missing = set(REQUIRED_PERMISSIONS) - found
    if missing:
        raise SeedError(f"Permissions manquantes : {sorted(missing)}")


def check_no_role_collision(cur, name: str) -> None:
    cur.execute(
        "SELECT 1 FROM public.roles "
        "WHERE organization_id = %s AND lower(name) = lower(%s)",
        (ORG_ID, name),
    )
    if cur.fetchone() is not None:
        raise SeedError(f"Rôle '{name}' déjà présent dans l'organisation.")


def check_no_email_collision(cur, email: str) -> None:
    cur.execute(
        "SELECT 1 FROM public.users WHERE lower(email) = lower(%s)",
        (email,),
    )
    if cur.fetchone() is not None:
        raise SeedError(f"Email '{email}' déjà présent.")


# ---------------------------------------------------------------------------
# Insertions
# ---------------------------------------------------------------------------

def insert_role(cur, name: str, description: str):
    cur.execute(
        """
        INSERT INTO public.roles (organization_id, name, description, is_system)
        VALUES (%s, %s, %s, FALSE)
        RETURNING id
        """,
        (ORG_ID, name, description),
    )
    return cur.fetchone()[0]


def insert_role_permissions(cur, role_id, permissions: list[str]) -> None:
    for code in permissions:
        cur.execute(
            """
            INSERT INTO public.role_permissions
                (organization_id, role_id, permission_code)
            VALUES (%s, %s, %s)
            """,
            (ORG_ID, role_id, code),
        )


def insert_user(cur, email: str):
    cur.execute(
        """
        INSERT INTO public.users (email, status)
        VALUES (%s, 'active')
        RETURNING id
        """,
        (email,),
    )
    return cur.fetchone()[0]


def insert_membership(cur, user_id):
    cur.execute(
        """
        INSERT INTO public.memberships
            (organization_id, user_id, status)
        VALUES (%s, %s, 'active')
        RETURNING id
        """,
        (ORG_ID, user_id),
    )
    return cur.fetchone()[0]


def insert_membership_role(cur, membership_id, role_id) -> None:
    cur.execute(
        """
        INSERT INTO public.membership_roles
            (organization_id, membership_id, role_id)
        VALUES (%s, %s, %s)
        """,
        (ORG_ID, membership_id, role_id),
    )


# ---------------------------------------------------------------------------
# Point d'entrée
# ---------------------------------------------------------------------------

def main() -> int:
    password = None
    try:
        password = getpass.getpass(
            "Mot de passe PostgreSQL pour securebiz_user (saisie masquée) : "
        )
        if not password:
            print("ERREUR : mot de passe vide.", file=sys.stderr)
            return 2

        with psycopg.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=password,
            connect_timeout=5,
            autocommit=False,
        ) as conn:
            with conn.cursor() as cur:
                # --- Contrôles préalables ---
                check_organization_exists(cur)
                check_permissions_present(cur)
                check_no_role_collision(cur, OWNER_ROLE_NAME)
                check_no_role_collision(cur, MEMBER_ROLE_NAME)
                check_no_email_collision(cur, DEMO_OWNER_EMAIL)
                check_no_email_collision(cur, DEMO_MEMBER_EMAIL)

                # --- Création des rôles ---
                owner_role_id = insert_role(
                    cur, OWNER_ROLE_NAME, "Rôle administrateur de démonstration"
                )
                member_role_id = insert_role(
                    cur, MEMBER_ROLE_NAME, "Rôle membre de démonstration"
                )
                insert_role_permissions(cur, owner_role_id, OWNER_PERMISSIONS)
                insert_role_permissions(cur, member_role_id, MEMBER_PERMISSIONS)

                # --- Création des utilisateurs ---
                owner_user_id = insert_user(cur, DEMO_OWNER_EMAIL)
                member_user_id = insert_user(cur, DEMO_MEMBER_EMAIL)

                # --- Memberships ---
                owner_membership_id = insert_membership(cur, owner_user_id)
                member_membership_id = insert_membership(cur, member_user_id)

                # --- Affectations de rôles ---
                insert_membership_role(cur, owner_membership_id, owner_role_id)
                insert_membership_role(cur, member_membership_id, member_role_id)

            # Le gestionnaire de contexte commit si tout réussit,
            # et rollback automatiquement en cas d'exception.

    except SeedError as exc:
        print(f"ABANDON (rollback) : {exc}", file=sys.stderr)
        return 1
    except psycopg.Error as exc:
        print(
            f"ERREUR PostgreSQL (rollback) : {type(exc).__name__}",
            file=sys.stderr,
        )
        return 1
    except KeyboardInterrupt:
        print("Interrompu par l'utilisateur (rollback).", file=sys.stderr)
        return 130
    finally:
        # Réduit la durée de vie de la référence Python au secret.
        password = None

    print("Seed IAM terminé avec succès.")
    print(f"  Organisation     : {ORG_ID}")
    print(f"  Rôle owner       : {owner_role_id} ({len(OWNER_PERMISSIONS)} permissions)")
    print(f"  Rôle member      : {member_role_id} ({len(MEMBER_PERMISSIONS)} permissions)")
    print(f"  User owner       : {owner_user_id}")
    print(f"  User member      : {member_user_id}")
    print(f"  Membership owner : {owner_membership_id}")
    print(f"  Membership member: {member_membership_id}")
    print("Credentials NON créés (voir scripts/provision_user.py).")
    return 0


if __name__ == "__main__":
    sys.exit(main())