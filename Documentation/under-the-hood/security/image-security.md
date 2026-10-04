# CRIU Image Security & State Restoration

## Overview

CRIU (Checkpoint/Restore In User-space) image files contain complete serialized
process state, including raw memory pages, CPU register states, file
descriptors, network credentials, and kernel security metadata. Because image
files capture snapshots of in-memory data, they often contain sensitive
plaintext secrets, such as TLS session keys, API tokens, user passwords, and
decrypted application state.

To perform low-level process reconstruction, `criu restore` typically runs with
elevated capabilities (such as `CAP_SYS_ADMIN` or `CAP_CHECKPOINT_RESTORE`).
**CRIU explicitly assumes that all image files provided to it are authentic,
confidential, and have not been tampered with or inspected by an untrusted
actor.**

## State Restoration & Security Boundaries

### 1. Accurate State Reconstruction

CRIU's core guarantee is to **faithfully restore processes to the exact state
they were in when checkpointed**, including their full security context
(UID/GID, capabilities, Linux Security Modules like SELinux and AppArmor
profiles, seccomp filters, namespaces, cgroups, etc.).

CRIU relies entirely on the metadata stored within the image files to
reconstruct these security boundaries.

### 2. The Privilege Risk of Image Modification

Because CRIU accurately applies the security attributes defined inside the
image files using its own execution privileges:

*   **Image contents dictate restored privileges:** An attacker who can modify
    or craft image files can alter the serialized credential metadata (e.g.,
    modifying effective UIDs or adding capability caps in `creds-*.img`).
*   **Arbitrary Code Execution & Escalation:** When `criu restore` executes
    with root or elevated capabilities, a crafted image can instruct CRIU to
    restore the target process with those same elevated privileges. Even
    without directly altering credentials, modifying serialized CPU register
    instruction pointers (`core-*.img`) or memory payloads (`pages-*.img`)
    enables arbitrary code execution at whatever privilege level the restored
    process or container is assigned.

### 3. Information Disclosure Risk

Because image files store complete dumps of process memory and OS state,
unauthorized read access to CRIU image files is equivalent to reading process
memory via `ptrace` or inspecting live kernel core dumps. An untrusted actor
with read access can extract secrets and security-critical data directly from
the unencrypted memory images.

## Design Assumptions & Non-Goals

*   **No Protection Against Malicious Image Tampering:** CRIU is designed to
    deserialize trusted state efficiently, not to act as a security
    sanitization boundary against intentionally corrupted, fuzzed, or malicious
    image files. CRIU parses Protocol Buffer (`protobuf`) structures and binary
    payloads directly in privileged contexts; untrusted input could trigger
    parser faults or unexpected restoration behaviors.
*   **Integrity and Confidentiality Must Be Enforced Externally:** Currently,
    CRIU does not natively sign or encrypt image sets. Authenticity, integrity,
    and privacy checks must be handled by the container runtime, orchestrator,
    or storage layer before `criu restore` is invoked.

## Operational Recommendations

Because CRIU relies on the integrity and privacy of the input image set to
enforce process security boundaries, operators must ensure image authenticity,
integrity, and confidentiality **before** process restoration begins.

Depending on your deployment architecture, enforce the following core
principles:

*   **Treat Image Files as Executables:** Restoring an unverified image carries
    the exact same security risk as executing an untrusted binary with the
    privileges of the `criu` tool. An attacker can alter serialized registers
    or memory to execute arbitrary code upon restoration.
*   **Prevent Unauthorized Access:** Secure the entire lifecycle of the image
    files across local storage, network transit, and remote registries.
*   **Enforce Cryptographic Verification & Encryption:** In environments where
    images travel over untrusted networks, reside in shared storage, or cross
    domain boundaries, always verify integrity and origin via cryptographic
    mechanisms prior to calling `criu restore`.

## Ongoing & Future Enhancements

To make securing image artifacts simpler and more seamless for container
runtimes and orchestrators, the CRIU team is actively exploring and
developing:

*   **Native Image Encryption & Decryption:** Integrating inline cryptographic
    routines directly into CRIU to encrypt state data at checkpoint time and
    decrypt it during restore.
*   **Built-in Integrity Verification:** Combining encryption with authenticated
    payload checks (e.g., AEAD ciphers) to automatically detect any tampering
    or corruption of image files before process reconstruction begins.

This native mechanism will allow users to protect sensitive process memory in
transit and at rest while ensuring that modified or unauthorized images are
automatically rejected at the restore boundary.
