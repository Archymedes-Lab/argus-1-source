# Sonia's release handoff

Verified on 2026-11-09: `soniAineza4` has admin access to
`Archymedes-Lab/argus-1` and `chrisnkuno/archymedes-site`. Her public key is
listed in `release/allowed_signers`; both repositories' `ARGUS_RELEASE_SIGNERS`
variables and the owner's local audit pin contain this fingerprint:

```text
SHA256:uwHiPSxc5L0s5E/Hspk2FLAUP5UZKi5kDFciut+Fy3I
```

No additional GitHub grant or replacement key is needed. Her private key's
availability, passphrase and Vercel access must be checked on her own machine.

## Prepare your machine

1. Use your own GitHub account (`gh auth status`) and checkout of the shared
   repository, with remote `org` pointing to `Archymedes-Lab/argus-1`.
2. Check your existing public key:
   `ssh-keygen -lf ~/.config/argus-release/signing_key.pub`.
   It must match the fingerprint above. Keep the passphrase-protected private
   key on your machine. A different key needs the process in
   [RELEASER-KEYS.md](RELEASER-KEYS.md).
3. Install the tools listed in [RELEASING.md](RELEASING.md): `gh`, `7z`, Bun
   and the Vercel CLI. Clone `chrisnkuno/archymedes-site` to
   `~/archymedes-site`; set that checkout's git name and GitHub email to your
   own identity. Log into your own Vercel account and link that checkout to
   the existing production **archymedes-site** project. Confirm project access
   before starting; a GitHub admin grant alone does not establish Vercel access.
4. Create your local pin file using the admin-maintained repository variable:

   ```sh
   mkdir -p -m 700 ~/.config/argus-release
   gh variable get ARGUS_RELEASE_SIGNERS -R Archymedes-Lab/argus-1 \
     > ~/.config/argus-release/trusted_signers
   chmod 600 ~/.config/argus-release/trusted_signers
   ```

   Compare both fingerprints with the other cofounder over the established
   second channel before trusting the file.

## Build and validate before signing

Push the reviewed release commit to a `release-test/*` branch on `org`.
Watch its **Release build** run to completion. All builds, install tests,
regression checks, assembly and content gates must pass. Review the manifest
commit, change report and remaining validation gaps before signing.

For a release touching `desktop/`, run the browser check in
[RELEASING.md](RELEASING.md) and require a passed native Windows harness in
the release builder or its opt-in `test/windows-native/*` CI job. The owner's
local test executable was blocked by Defender's prevalence rule in the prior
session; that local attempt remains unrun. The disposable CI runner provides
the native execution evidence without changing the owner's policy. Check the
harness output, test count and final job result, not only compilation.

The current preparation stops before signing. Once the release is ready and
you are ready to publish, the final interactive step is your own key passphrase:

```sh
bash release/publish_dry_run.sh RUN_ID
```

This command downloads and gates the successful run again, checks its sums,
asks for your signing passphrase, then publishes, deploys and verifies the
live downloads. **It publishes after signing**; do not use it merely to stage
an unsigned candidate. A failed build, gate, signature or readback remains a
failure. Report the run URL, commit, signer and live readback result.

`ARGUS_RELEASE_KEY`, `ARGUS_SITE_REPO`, `ARGUS_PUBLISH_DIR` and `ARGUS_7Z_DIR`
can override local paths. For a tagged release, use the separate signed
host-attestation and draft procedure in [RELEASING.md](RELEASING.md).
