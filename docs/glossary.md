# Glossary

| Term | Definition |
| :--- | :--- |
| **API** | Interface allowing software components to communicate. |
| **FastAPI** | Python framework used to build the HTTP API. |
| **Uvicorn** | ASGI server used to run the FastAPI application. |
| **PostgreSQL** | Relational database management system. |
| **Psycopg** | Python library for connecting to PostgreSQL. |
| **Docker** | Containerization platform. |
| **Docker Compose** | Tool for defining and running Docker services. |
| **IAM** | Identity and Access Management: managing identities and access. |
| **Tenant** | Isolated customer organization or workspace in a multi-tenant application. |
| **Membership** | Relationship between a user and an organization. |
| **RBAC** | Role-Based Access Control: access control based on roles. |
| **Permission** | Specific right associated with an action or a resource. |
| **RLS** | Row-Level Security: PostgreSQL policies controlling which rows are accessible. |
| **Migration** | Versioned modification of the database schema or data. |
| **Least Privilege** | Principle of granting only the necessary rights. |
| **DevSecOps** | Integration of security practices into the DevOps lifecycle. |
| **Password Hash** | Output of a hashing function adapted to passwords; it is not the cleartext password. |
| **HashiCorp Vault** | Secrets management system used to store the Ed25519 private key and sign contexts. |
| **Transit Engine** | Vault engine used specifically for cryptographic operations (encryption, signing). |
| **pgsodium** | PostgreSQL extension providing modern cryptographic functions, including Ed25519 signature verification. |
| **Ed25519** | Fast and highly secure asymmetric signature algorithm (public key / private key). |
| **Signed Context** | Message containing identity (User ID, Org ID) with a cryptographic signature proving it has not been tampered with. |
| **Fail-fast** | Design principle where an application stops immediately if its configuration is invalid, instead of starting in a degraded state. |
| **JWT** | JSON Web Token: signed token used to transmit identity claims between parties. (Planned, not yet implemented.) |
| **`xid8`** | PostgreSQL 64-bit transaction identifier type, used to bind the security context to a transaction. |
| **`kid`** | Key Identifier: unique identifier of an Ed25519 public key stored in `auth_security.public_keys`. |
| **`jti`** | JWT ID: unique identifier of a signed context, used for anti-replay protection. |
| **`FORCE ROW LEVEL SECURITY`** | PostgreSQL option that applies RLS policies even to the owner of the table. |
| **`SECURITY DEFINER`** | PostgreSQL function attribute where the function runs with the privileges of its owner. |
| **`BYPASSRLS`** | PostgreSQL role attribute allowing the role to bypass RLS policies. Not granted to `securebiz_app` or `securebiz_auth`. |
| **`NOLOGIN`** | PostgreSQL role attribute preventing the role from connecting to the database. Used for `securebiz_owner`. |