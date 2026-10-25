# Fresh public trust inputs for native demos

D01 and D09 exercise the normal signed USB import and offline freshness policy.
The embedded signed passport and DTC vectors are public cryptographic test
inputs. Their trust package creation dates do not advance when a generator runs.
A valid signature and a distant expiry do not make an old package fresh.

Refresh the trust envelope through remote KMS custody. Keep the CSCA/DSC and
signed document bytes unchanged. Never generate or export a private key on the
operator host, increase the offline age limit to accommodate an old fixture, or
describe these engineering vectors as independent hardware or production data.

1. Obtain the public Ed25519 signing and distinct recovery keys from the
   authorized, nonexportable KMS keys. Put their base64 public bytes in
   `usb-signing-public-key.txt` and `usb-recovery-public-key.txt` in a public key
   directory.
2. Run `marty-demo-fixtures --prepare-trust dtc <public-key-directory> <new-directory>`.
   Use `emrtd` for D01. This reuses the production Rust canonical payload and
   signer identifiers, preserving the embedded public anchors. It writes
   `kms-input.json` for the remote signing operation.
3. Send that request to the authorized KMS signing path using the existing secure
   credential mechanism. Save only the base64 detached signature to a public
   signature file; credentials and private key material are never generator
   arguments or artifact inputs.
4. Run `marty-demo-fixtures --complete-trust <prepared-directory> <signature-file>`.
   It verifies the actual signature, signer binding, expiry and freshness before
   replacing the unsigned preparation. A stale, future-dated or wrong signature
   cannot produce an accepted package.
5. Place the completed public input directories under `<root>/dtc` and
   `<root>/emrtd`, then set `MARTY_DEMO_PUBLIC_TRUST_DIRECTORY=<root>` for the
   generators. An explicit missing or invalid directory fails instead of falling
   back to another trust root. The generators still validate the original signed
   document against the selected CSCA.

Retain the resulting public input hashes with the run's regeneration inputs.
Use fresh isolated native storage and scoped beta API authority for each run;
revoke the producer afterward and retain immutable server audit history. These
operations establish local functional evidence. Release, hardware, recording and
publication qualification remain separate.
