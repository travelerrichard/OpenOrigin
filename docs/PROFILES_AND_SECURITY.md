# Profiles and Security Layers

## Profiles
Profiles define BOTH:
1. Metadata handling
2. Security layers applied

| Profile | Metadata | Security Layers |
|---------|----------|-----------------|
| preserve | Keep all metadata. | None |
| preserve_signed | Keep all metadata. | Official signing |
| redact | Remove GPS, device IDs, CreatorTool; coarsen CreateDate. | None |
| redact_signed | Same as redact. | Official signing |
| redact_signed_log | Same as redact_signed. | Official signing + log hash |

## Security Layers
- `sign_official`: Sign with the official GPG key for this tool.
- `sign_user`: Sign with your own GPG key (`--user-key <path>` required).
- `log_hash`: Send package hash to a public transparency log.

## Overrides from CLI Flags
```bash
# Enable official signing even if the profile disables it
python originals_etl.py video.mov --profile redact --sign-official

# Disable logging even if profile enables it
python originals_etl.py video.mov --profile redact_signed_log --no-log-hash

# Add user signing with a specific key
python originals_etl.py video.mov --profile preserve_signed --sign-user --user-key ~/.gnupg/mykey.asc
```

## Profile Definitions
Profiles are stored in `profiles/` as JSON files:
- name
- description
- metadata_policy (`keep_all` or `safe_defaults`)
- security_layers (`sign_official`, `sign_user`, `log_hash`)

## Verify a Package
1. Obtain the `.zip` and (if present) `.sig` files.
2. Verify signatures with GPG.
3. If `log_hash` enabled, confirm the hash in the transparency log.
