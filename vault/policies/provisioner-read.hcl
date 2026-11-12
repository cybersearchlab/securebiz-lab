# ============================================================================
# SecureBiz Lab -- Vault policy: provisioner-read
# ============================================================================
# Minimal read policy for the provisioning script (scripts/provision_user.py).
# It is NOT used by the one-shot bootstrap script
# (scripts/set_provisioner_password.py), which requires a Vault token with
# write access to the same path.
#
# Grants:
#   - read on secret/data/securebiz/provisioner (the PostgreSQL password)
#
# Does NOT grant:
#   - any write, list, or delete capability
#   - access to any other secret (JWT, transit, etc.)
#   - any sys/* capability
#
# This policy is attached to the dedicated token used by the provisioning
# script. The script never uses the root token.
# ============================================================================

path "secret/data/securebiz/provisioner" {
  capabilities = ["read"]
}
