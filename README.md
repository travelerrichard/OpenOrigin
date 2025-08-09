
## **OpenOrigin – Simple, Trusted Sharing of Original Files**

**OpenOrigin** is a community-friendly way to share media in its most authentic form — with the quality and details needed for accurate review, while giving the creator control over what’s shared.

When people see important videos, images, or documents online, the first question is often: *"Can we trust this?"*
OpenOrigin helps answer that question by making it easy to provide an **Original File Package** alongside your post.

---

### **Why it Matters**

* **Trust** – Original files allow communities, journalists, and researchers to verify what they’re seeing.
* **Transparency** – Helpful details like capture date, device type, or file history can be preserved.
* **Privacy Control** – Sensitive information, like GPS location, can be removed before sharing.
* **Local-Only Processing** – Everything happens on your own computer. Nothing you choose to redact is ever sent anywhere or stored by OpenOrigin.
* **Ease of Use** – It’s designed to be as simple as drag-and-drop, so anyone can use it.

---

### **How It Works (in Plain Language)**

1. You choose your original file — it could be a video, a photo, a document, or any other media.
2. OpenOrigin **processes it entirely on your device**:

   * Keeps full quality.
   * Optionally removes private data.
   * Adds a short “manifest” file that lists what’s included and any changes made.
3. You post your file package link alongside your content.
4. Others can download and **see exactly what you shared** — with no guesswork.

---

### **Extra Peace of Mind**

For creators who want stronger trust signals, OpenOrigin can also:

* **Digitally sign** the package so people know it hasn’t been changed.
* **Log the package fingerprint** in a public list so anyone can check its authenticity.

These are optional features — you can keep things simple or go all-in on verification.

---

### **Who Can Benefit**

* **Community moderators** who want clearer standards for evidence.
* **Posters** who want their content taken seriously.
* **Investigators, journalists, and fact-checkers** who need the best possible source material.

---

Here’s a comparison table showing how **OpenOrigin** relates to related frameworks and tools:

| Feature / Aspect           | **OpenOrigin**                                                                                     | **C2PA**                                                                          | **InVID**                                                                 | **Forensic Packaging Standards**                                          |
| -------------------------- | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| **Primary Purpose**        | Creator-side tool to package original media with optional metadata redaction and integrity proofs. | Industry standard for embedding tamper-evident provenance metadata in media.      | Investigator/journalist tool to verify and analyze online media.          | Legal/evidentiary chain-of-custody preservation for digital files.        |
| **Who Uses It**            | Any poster, mod, or content creator; journalists; community members.                               | Large media companies, camera manufacturers, software vendors.                    | Journalists, fact-checkers, researchers.                                  | Law enforcement, legal teams, forensic analysts.                          |
| **Processing Location**    | **Entirely local** — nothing leaves the user’s device unless they choose to upload.                | Embedded in devices/software; often cloud-integrated for credential verification. | Runs locally in browser extension, but fetches media from online sources. | Local or secured forensic lab environments.                               |
| **Metadata Handling**      | User chooses to preserve or redact; redaction is built into workflow.                              | Preserves all relevant provenance data; redaction is not the goal.                | Reads metadata for analysis; not designed to modify or redact.            | Preserves all metadata for legal admissibility.                           |
| **Integrity Verification** | Optional digital signatures, package hash logging in public transparency log.                      | Cryptographic signatures embedded in media; verifiable via standard.              | No signing; focuses on inspection tools.                                  | Full cryptographic hash recording, evidence seals, chain-of-custody logs. |
| **Complexity**             | Low — designed for non-technical users.                                                            | High — requires device/vendor integration and adherence to detailed standard.     | Moderate — requires user understanding of verification workflows.         | High — requires forensic knowledge, specialized tools, legal compliance.  |
| **Media Types Supported**  | Any file type (video, image, document, etc.).                                                      | Typically image/video, expanding to other formats.                                | Primarily video and image.                                                | Any digital file, including non-media data.                               |
| **Adoption Model**         | Open-source, community-driven; easy to add to subreddit/wiki rules.                                | Industry coalition; adoption through device/software integration.                 | Free tool promoted in journalism/fact-checking circles.                   | Institutional; standardized procedures in legal/forensic fields.          |
| **Cost & Accessibility**   | Free, open-source, no special hardware.                                                            | Varies — usually bundled in commercial tools/hardware.                            | Free to use.                                                              | Proprietary or specialized (can be costly).                               |

---


# Originals ETL — Minimum-ETL for Sharing Original Media

Create an **Original File Package** (`*_package.zip`) for analysis:
- Lossless rewrap to `.mp4` where possible
- Metadata JSON (full or redacted)
- SHA-256 hashes
- `manifest.json` with actions taken
- **Profiles** now include optional security layers (signing, logging)

## Quick start
```bash
cd originals-etl/cli
python originals_etl.py /path/to/video.mov --profile redact
```
