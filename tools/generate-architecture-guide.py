#!/usr/bin/env python3
"""Generate the Tarn Architecture Guide PDF.

Run:
    python tools/generate-architecture-guide.py

Output: docs/tarn-architecture-guide.pdf

Requires: reportlab (pip install reportlab).

The content lives in CONTENT below as a structured list of section objects.
Edit content + re-run to regenerate. The script is idempotent — same input
produces byte-identical PDF (modulo timestamps).
"""

from datetime import date
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    PageBreak,
    PageTemplate,
    Paragraph,
    Preformatted,
    Spacer,
    Table,
    TableStyle,
)


# ============ STYLES ============

def make_styles():
    base = getSampleStyleSheet()
    body_color = colors.HexColor('#1a1a1a')
    accent = colors.HexColor('#2c5f2d')  # muted green — Tarn / alpinism cue
    muted = colors.HexColor('#6b6b6b')
    code_bg = colors.HexColor('#f4f4f2')
    code_border = colors.HexColor('#dcdcd5')

    styles = {
        'Title': ParagraphStyle(
            'Title', parent=base['Title'],
            fontName='Helvetica-Bold', fontSize=42, leading=48,
            textColor=accent, alignment=TA_CENTER, spaceAfter=18,
        ),
        'Subtitle': ParagraphStyle(
            'Subtitle', parent=base['Normal'],
            fontName='Helvetica', fontSize=18, leading=22,
            textColor=body_color, alignment=TA_CENTER, spaceAfter=8,
        ),
        'Tagline': ParagraphStyle(
            'Tagline', parent=base['Normal'],
            fontName='Helvetica-Oblique', fontSize=12, leading=16,
            textColor=muted, alignment=TA_CENTER, spaceAfter=24,
        ),
        'Date': ParagraphStyle(
            'Date', parent=base['Normal'],
            fontName='Helvetica', fontSize=11, leading=14,
            textColor=muted, alignment=TA_CENTER,
        ),
        'H1': ParagraphStyle(
            'H1', parent=base['Heading1'],
            fontName='Helvetica-Bold', fontSize=20, leading=24,
            textColor=accent, spaceBefore=20, spaceAfter=12,
            keepWithNext=True,
        ),
        'H2': ParagraphStyle(
            'H2', parent=base['Heading2'],
            fontName='Helvetica-Bold', fontSize=14, leading=18,
            textColor=body_color, spaceBefore=14, spaceAfter=6,
            keepWithNext=True,
        ),
        'H3': ParagraphStyle(
            'H3', parent=base['Heading3'],
            fontName='Helvetica-Bold', fontSize=11.5, leading=15,
            textColor=body_color, spaceBefore=10, spaceAfter=4,
            keepWithNext=True,
        ),
        'Body': ParagraphStyle(
            'Body', parent=base['Normal'],
            fontName='Helvetica', fontSize=10.5, leading=15,
            textColor=body_color, alignment=TA_JUSTIFY, spaceAfter=8,
        ),
        'Bullet': ParagraphStyle(
            'Bullet', parent=base['Normal'],
            fontName='Helvetica', fontSize=10.5, leading=15,
            textColor=body_color, leftIndent=18, bulletIndent=4,
            spaceAfter=4,
        ),
        'Code': ParagraphStyle(
            'Code', parent=base['Code'],
            fontName='Courier', fontSize=8.5, leading=12,
            textColor=body_color, backColor=code_bg, borderColor=code_border,
            borderWidth=0.5, borderPadding=8, leftIndent=0, rightIndent=0,
            spaceBefore=6, spaceAfter=10,
        ),
        'Callout': ParagraphStyle(
            'Callout', parent=base['Normal'],
            fontName='Helvetica-Oblique', fontSize=10, leading=14,
            textColor=accent, leftIndent=14, rightIndent=14,
            borderColor=accent, borderWidth=0,
            spaceBefore=6, spaceAfter=10,
        ),
        'TocEntry': ParagraphStyle(
            'TocEntry', parent=base['Normal'],
            fontName='Helvetica', fontSize=11, leading=18,
            textColor=body_color, leftIndent=8,
        ),
        'TocSub': ParagraphStyle(
            'TocSub', parent=base['Normal'],
            fontName='Helvetica', fontSize=10, leading=15,
            textColor=muted, leftIndent=24,
        ),
        'Footer': ParagraphStyle(
            'Footer', parent=base['Normal'],
            fontName='Helvetica', fontSize=9, leading=11,
            textColor=muted, alignment=TA_CENTER,
        ),
    }
    return styles


# ============ CONTENT ============

# Each entry is one of:
#   ('h1', text)      — top-level section
#   ('h2', text)      — sub-section
#   ('h3', text)      — sub-sub-section
#   ('p', text)       — body paragraph (HTML allowed: <b>, <i>, <code>)
#   ('b', text)       — bullet
#   ('code', text)    — code block (preformatted)
#   ('callout', text) — pull-quote / emphasis
#   ('spacer',)       — vertical breathing room
#   ('pagebreak',)    — explicit page break
#   ('table', headers, rows) — simple two-column table

CONTENT = [
    # ============ EXEC SUMMARY ============
    ('h1', 'Executive summary'),
    ('p',
     "Tarn is a platform for permanent, encrypted, user-owned data. It is "
     "infrastructure — not an end-user product — that any application can build "
     "on to give its users data that is theirs in a way that survives the app, "
     "the platform, and the company."),
    ('p',
     "Three properties define Tarn:"),
    ('b',
     "<b>Permanent.</b> User data is stored on Arweave, a permanent decentralized "
     "ledger. Once written, it is there forever, signed and timestamped, "
     "independent of any company's continued operation."),
    ('b',
     "<b>Encrypted.</b> All content is encrypted client-side before it leaves the "
     "user's device. The Tarn service never sees plaintext, never holds the "
     "keys, and cannot be coerced into producing user content even under legal "
     "compulsion."),
    ('b',
     "<b>User-owned.</b> Authentication and decryption are derived from secrets "
     "the user holds: their email + password, plus a recovery phrase issued at "
     "signup. There is no provider in the trust loop. If Tarn disappears, the "
     "user can still decrypt their data from raw Arweave."),
    ('p',
     "The user's content layer is augmented by a sharing layer that lets users "
     "selectively share specific items with specific people, end-to-end "
     "encrypted, without exposing their identity graph to the storage provider."),
    ('p',
     "This document is a human-readable architecture guide. It is intended for "
     "technical readers who want to understand what Tarn is, how it is shaped, "
     "and what trade-offs are baked into the design. For the formal protocol "
     "specification, see <i>TARN_PROTOCOL.md</i> in the repository."),

    ('pagebreak',),

    # ============ WHY ============
    ('h1', '1. Why Tarn exists'),
    ('p',
     "Most consumer software treats user data as a side effect of providing a "
     "service. The data lives in the company's database, encrypted (if at all) "
     "with keys the company controls. The implicit contract is: <i>trust the "
     "company.</i> Trust them not to read your messages. Trust them to stay in "
     "business. Trust them not to pivot, sell to a worse owner, or be coerced "
     "by a government. Trust them, year after year, indefinitely."),
    ('p',
     "When that trust breaks — and it eventually does, for many users — the "
     "data is held hostage. Photos in Facebook. Email in Google. Notes in "
     "Evernote. Medical history in a portal whose terms you never re-read. "
     "Even when companies act in good faith, services shut down (Google "
     "Reader, Vine, every product Yahoo touched), and the data goes with them."),
    ('p',
     "Tarn flips the model. The data layer is not the company's database; it "
     "is the user's. Encryption happens client-side with keys the user holds. "
     "Permanence is provided by Arweave, not by Tarn's continued operation. "
     "If Tarn the service stops existing tomorrow, every user can still "
     "recover their data with nothing more than their credentials."),
    ('p',
     "The result: applications built on Tarn inherit a stronger privacy and "
     "ownership story than they could plausibly claim alone. The application "
     "developer doesn't have to be trustworthy — the cryptography is."),

    # ============ TRUST MODEL ============
    ('h1', '2. Trust model and design principles'),
    ('p',
     "Tarn's design is shaped by six principles. Every architectural decision "
     "ultimately answers to these."),
    ('h3', 'Zero knowledge'),
    ('p',
     "The Tarn API never sees plaintext. All encryption happens on the client "
     "before bytes leave the user's device. Even with full administrative "
     "access to the Tarn database, an operator cannot decrypt user content."),
    ('h3', 'No infrastructure dependency for recovery'),
    ('p',
     "If Tarn disappears, users can still decrypt their data. Tarn's database "
     "is a cache that can be rebuilt from raw Arweave, and any client with the "
     "user's credentials can read directly from Arweave without going through "
     "Tarn at all."),
    ('h3', 'User-derived keys'),
    ('p',
     "All cryptographic material is derived from secrets the user holds: their "
     "email, password, and recovery phrase. Tarn cannot reset a password "
     "(the password <i>is</i> the key, not a check against a stored hash) and "
     "cannot recover an account on behalf of a user."),
    ('h3', 'Per-app isolation'),
    ('p',
     "The same email and password used in two different apps produce two "
     "fully independent identities. A user's Bookish account and their Cellar "
     "account share no derivable keys, no lookup tags, and no observable "
     "linkage on Arweave."),
    ('h3', 'Permanence over deletion'),
    ('p',
     "Data on Arweave is immutable. Tarn does not pretend otherwise. Users can "
     "stop publishing, rotate keys forward to make old data inaccessible to "
     "future credentials, or unfollow connections — but they cannot "
     "retroactively un-publish what was already encrypted to a recipient. "
     "The protocol and UX make this property explicit rather than hiding it."),
    ('h3', 'Honest about residual leaks'),
    ('p',
     "Tarn does not promise more than it can deliver. Some metadata "
     "(connection-request timing, account existence via discoverability "
     "lookup) is observable to interested parties; this is documented "
     "explicitly in protocol notes rather than papered over."),

    # ============ ARCHITECTURE ============
    ('h1', '3. System architecture'),
    ('p',
     "Tarn has four layers. The bottom two are what makes data permanent and "
     "tamper-evident; the top two are what makes it usable."),
    ('code',
     "User device                       User device                       User device\n"
     "        \\                              |                              /\n"
     "         +------> Client SDK <----------+----------> Client SDK <-----+\n"
     "                       |                                   |\n"
     "                       v                                   v\n"
     "                +-------------------------------------------------+\n"
     "                |  Tarn API (Cloudflare Workers + D1 cache)       |\n"
     "                |  - challenge/response auth, JWT issuance        |\n"
     "                |  - tag-keyed cache over Arweave canonical       |\n"
     "                |  - bundles + signs uploads to Arweave           |\n"
     "                +-------------------------------------------------+\n"
     "                       |                                   ^\n"
     "                  bundles signed                     reads / GraphQL\n"
     "                  data items                         (cold-bootstrap)\n"
     "                       v                                   |\n"
     "                +-------------------------------------------------+\n"
     "                |  Arweave (permanent, public, encrypted blobs)   |\n"
     "                |  - canonical store of all user content          |\n"
     "                |  - signed by Tarn-bundler wallet                |\n"
     "                |  - opaque ciphertext from any observer's view   |\n"
     "                +-------------------------------------------------+"
    ),
    ('h2', 'Layer 1 — Arweave (canonical store)'),
    ('p',
     "All user content lives on Arweave as encrypted blobs. Once written, "
     "blobs are permanent and tamper-evident. Tarn signs uploads via a "
     "single shared bundler wallet, which means Arweave-level observers see "
     "<i>that</i> Tarn customer activity is happening but cannot link writes "
     "to specific users without help from the protocol layer."),
    ('h2', 'Layer 2 — Tarn API (cache + write proxy)'),
    ('p',
     "Cloudflare Workers serve as the read/write hot path. A D1 database "
     "caches Arweave blobs by tag for sub-100ms reads. The API does <b>not</b> "
     "see plaintext — it stores opaque ciphertext bytes — and is structurally "
     "rebuildable from Arweave (cold-bootstrap path included)."),
    ('p',
     "The API also handles authentication challenge-response, JWT issuance, "
     "rate limiting, and per-app rules enforcement. Apps register with Tarn "
     "and prove their identity via ECDSA challenge-response; user accounts "
     "do the same with their per-app signing key."),
    ('h2', 'Layer 3 — Client SDK'),
    ('p',
     "All cryptography happens in the SDK. Key derivation, content encryption, "
     "share-log signing, recovery PDF rendering, BIP39 phrase generation, "
     "HPKE handshakes — none of this is network-mediated. The SDK is published "
     "as a JavaScript library and runs in browsers and Node.js."),
    ('h2', 'Layer 4 — Application code'),
    ('p',
     "Applications (e.g., Bookish, the first app on Tarn) build their UX on "
     "top of the SDK. The SDK is intentionally product-neutral: it exposes "
     "primitives like \"create encrypted entry\", \"share content with a "
     "connection\", \"read share log\". Application code decides what to call "
     "those primitives in the user-facing UI."),

    ('pagebreak',),

    # ============ ACCOUNT MODEL ============
    ('h1', '4. Account model'),
    ('p',
     "An account in Tarn is identified by an (email, app_id) pair. The same "
     "email used across multiple apps produces multiple unrelated identities. "
     "Authentication uses a challenge-response signature; passwords are never "
     "transmitted to the server."),
    ('h2', 'Key derivation chain'),
    ('p',
     "From the user's two secrets — email and password — Tarn derives every "
     "key the system needs:"),
    ('code',
     "email + password\n"
     "      |\n"
     "      v   Argon2id (m=64MiB, t=3, p=1, salt=SHA-256(email))\n"
     "      |\n"
     "  master_key  (32 bytes, never leaves device)\n"
     "      |\n"
     "      +-- HKDF(info=\"lookup\")  --> credential_lookup_key  (server pseudonym)\n"
     "      +-- HKDF(info=\"encrypt\") --> credential_encryption_key (KEK)\n"
     "      +-- HKDF(info=\"sign\")    --> ECDSA P-256 signing keypair\n"
     "      +-- HKDF(info=\"share\")   --> X25519 sharing keypair\n"
     "\n"
     "Every HKDF call also includes app_id, so all sub-keys are app-scoped."
    ),
    ('p',
     "The key derivation function is Argon2id, a memory-hard KDF that resists "
     "brute force from GPUs and ASICs. Legacy accounts on PBKDF2 continue to "
     "work via a fallback path; new accounts always use Argon2id. The KDF "
     "version is recorded in the user's credential blob so the client knows "
     "which to use on subsequent logins."),
    ('h2', 'Per-app isolation'),
    ('p',
     "Every derivation embeds <code>app_id</code> in its HKDF info string. "
     "This means the same email + password used in app A and app B produce "
     "completely different lookup keys, encryption keys, signing keys, and "
     "sharing keys. From the protocol's view, the two accounts are unrelated. "
     "An Arweave observer scanning tags cannot link them; Tarn the service "
     "sees two separate accounts with no derivable connection."),
    ('h2', 'Authentication'),
    ('p',
     "Login is a challenge-response cycle. The client requests a challenge "
     "(receives a fresh nonce), signs the nonce with its app-scoped ECDSA "
     "private key, and returns the signature. The server verifies against the "
     "stored public key and issues a short-lived JWT. The user's password is "
     "never transmitted; the server stores no password hash."),
    ('callout',
     "Tarn cannot \"reset\" a password the way a traditional service can. "
     "There is no stored hash to compare against and no out-of-band recovery "
     "channel under Tarn's control. The password <i>is</i> half of the user's "
     "key material. The other half — the recovery phrase — exists for exactly "
     "this reason."),

    # ============ DATA ENCRYPTION ============
    ('h1', '5. Data encryption'),
    ('p',
     "User content is encrypted twice over: once with a per-content key (the "
     "CEK), which is itself wrapped under a generation-indexed data "
     "encryption key (the DEK). This two-layer pattern enables selective "
     "sharing and forward-secret rotation without re-encrypting existing data."),
    ('h2', 'The DEK chain'),
    ('p',
     "Each user has a chain of DEKs, one per generation. New accounts start "
     "at gen 1 with a randomly generated 32-byte key. On every credential "
     "change, a fresh DEK is appended at gen N+1. Old generations stay in the "
     "chain so that data written under them is still readable; new writes use "
     "the latest generation."),
    ('p',
     "The chain is wrapped under the user's <code>credential_encryption_key</code> "
     "(KEK) and stored in their credential blob on Arweave. Multi-factor wrapping: "
     "every chain entry is wrapped twice — once under the password-derived KEK, "
     "once under a recovery-phrase-derived KEK. Either factor independently "
     "unwraps the chain."),
    ('h2', 'Per-content CEKs'),
    ('p',
     "Each content blob carries its own CEK, randomly generated, used once to "
     "encrypt that blob's plaintext. The CEK is wrapped under the current-"
     "generation DEK and prepended to the ciphertext along with a 5-byte "
     "format magic prefix:"),
    ('code',
     "data_blob = magic(5) || wrapped_CEK(40) || iv(12) || ciphertext+tag\n"
     "where:\n"
     "    magic       = 0x54 0x41 0x52 0x4e 0x02   // ASCII \"TARN\" + version\n"
     "    wrapped_CEK = AES-KW(DEK_at_current_gen, CEK)\n"
     "    iv          = random_bytes(12)\n"
     "    ciphertext  = AES-256-GCM(CEK, iv, plaintext)"
    ),
    ('p',
     "The owner reads by unwrapping the CEK with their DEK and decrypting "
     "the ciphertext. A recipient who has been given the CEK directly (via "
     "the sharing layer — see §7) skips the wrapped_CEK portion and decrypts "
     "the same ciphertext blob with the CEK they were given. The owner never "
     "exposes their DEK; only specific CEKs are shared."),
    ('h2', 'Forward-secret rotation'),
    ('p',
     "When a user changes their password, the new credentials cannot decrypt "
     "data written before the change unless the user explicitly carries the "
     "old DEKs forward (which Tarn does, by design, so existing data stays "
     "readable). But future writes use a fresh DEK at the new generation, "
     "and an attacker with only the old credentials cannot derive that new "
     "DEK. The blast radius of a credential leak is bounded to data written "
     "before the rotation."),

    ('pagebreak',),

    # ============ RECOVERY ============
    ('h1', '6. Account recovery'),
    ('p',
     "Tarn issues every user a 24-word recovery phrase at signup. This phrase "
     "is generated client-side from cryptographic randomness, never seen by "
     "Tarn, and serves as a parallel access path to the user's data: a "
     "different KEK that can independently unwrap the same DEK chain that the "
     "password-derived KEK protects."),
    ('h2', 'How the phrase is delivered'),
    ('p',
     "At signup the SDK generates the phrase, renders a printable PDF "
     "containing the phrase + instructions, and (by default, opt-in) emails a "
     "copy to the user. Tarn's API briefly handles the PDF in memory while "
     "forwarding it via an external email relay; nothing is persisted. The "
     "user is required to acknowledge that they have saved the phrase before "
     "the registration completes."),
    ('h2', 'How recovery works'),
    ('p',
     "If the user later loses their password, they enter the 24-word phrase "
     "into the SDK. The phrase derives a recovery KEK (Argon2id over the "
     "phrase + a per-account salt stored in the credential blob), and from "
     "there a recovery-specific lookup key and signing key. The user "
     "authenticates with the recovery signing key, unwraps the DEK chain "
     "via the recovery factor, sets new credentials, and re-wraps the chain "
     "under the new password KEK. All existing data is preserved; new "
     "credentials work going forward."),
    ('callout',
     "Email + password change is a routine convenience. Account recovery via "
     "phrase is the response to suspected compromise. Apps building on Tarn "
     "should communicate this distinction to users."),

    # ============ SHARING ============
    ('h1', '7. Sharing and connections'),
    ('p',
     "Users can selectively share encrypted content with other users, "
     "end-to-end. The sharing layer is built on the same primitives as the "
     "private content layer — Arweave for storage, per-content CEKs for "
     "encryption — extended with a few additional keys."),
    ('h2', 'Connections, not friends or follows'),
    ('p',
     "The Tarn protocol calls a relationship between two users a "
     "<i>connection</i>. The term is intentionally neutral: applications can "
     "present connections as friends, followers, contacts, or however suits "
     "their UX. The protocol-level relationship is mutual — both sides "
     "explicitly accept — and apps deliver asymmetric \"follow\" UX on top by "
     "combining the mutual primitive with a per-side mute filter."),
    ('h2', 'Connection handshake'),
    ('p',
     "Establishing a connection is a two-step exchange:"),
    ('b',
     "Alice sends a connection request to Bob: an HPKE-sealed payload "
     "(RFC 9180, DHKEM-X25519 + HKDF-SHA-256 + AES-256-GCM) addressed to "
     "Bob's published sharing public key."),
    ('b',
     "Bob accepts: an HPKE-sealed acceptance addressed to Alice's sharing "
     "public key, referencing the original request's nonce."),
    ('p',
     "After both messages are exchanged, both users add each other to their "
     "<i>connections record</i> — an encrypted Tarn data blob that lists "
     "their accepted connections. From this point on, both can publish "
     "share-log entries to each other."),
    ('h2', 'Per-pair share log'),
    ('p',
     "Each connection has two append-only share logs, one in each direction. "
     "Each log entry is encrypted under a per-pair AES-GCM key derived from "
     "the X25519 ECDH shared secret between the two parties' sharing "
     "keypairs. Entries are signed with the sender's identity key, and "
     "tagged on Arweave with stealth-addressed identifiers (HMAC under a "
     "per-pair seed) — meaning that an Arweave observer cannot link tags to "
     "specific user pairs without that seed."),
    ('p',
     "The five operation types are <code>add</code> (first-share a content "
     "item), <code>update</code> (publish a new version), <code>rotate</code> "
     "(change the per-content CEK), <code>remove</code> (unshare), and "
     "<code>snapshot</code> (full-state checkpoint for fast bootstrap). A "
     "sixth operation, <code>rotate_identity</code>, handles credential "
     "changes — see §8."),
    ('h2', 'Why per-pair instead of broadcast'),
    ('p',
     "Per-pair encryption means each share is encrypted individually for "
     "each recipient. This scales gracefully to hundreds of connections and "
     "preserves strong metadata privacy — the protocol does not reveal who "
     "shares what with whom, even to network observers. A separate broadcast "
     "primitive for influencer-scale public sharing is anticipated as future "
     "work; the current design optimizes for private-circle use cases where "
     "metadata privacy matters."),
    ('h2', 'Mute filter for asymmetric UX'),
    ('p',
     "Apps that want to present connections as Strava-style asymmetric "
     "follow (\"I follow you, but you don't have to follow me back\") layer a "
     "per-side mute filter on top of the mutual handshake. Muting a "
     "connection hides their content from the muting party's feed without "
     "affecting the underlying cryptographic relationship — the filter is "
     "purely a UI convention, persisted as an encrypted record so it syncs "
     "across the user's devices."),

    # ============ ROTATION ============
    ('h1', '8. Identity rotation'),
    ('p',
     "When a user changes their email or password, every key derived from "
     "their master key changes too — including their sharing keypair. This "
     "would normally break all existing connections: Alice's old sharing "
     "private key is gone, so the per-pair shared secrets her contacts had "
     "with her no longer work."),
    ('p',
     "To handle this transparently, Tarn uses a <i>rotation announcement</i> "
     "protocol. As part of the credential change, the SDK iterates over the "
     "user's connections and publishes a special "
     "<code>rotate_identity</code> operation to each connection's old "
     "share log, signed with the old signing key (which the SDK still has "
     "in memory) and containing the new sharing and signing public keys."),
    ('p',
     "The recipient picks up the announcement on their next read of the share "
     "log, verifies the signature against the cached old signing key, "
     "updates their connections record with the new public keys, and "
     "transparently switches to the new per-pair derivation for all future "
     "reads and writes. From the user's perspective, the credential change "
     "is a no-op: their connections are preserved, their data is still "
     "readable, and their contacts auto-reconcile."),
    ('callout',
     "The rotation flow assumes the old keys are not compromised at the "
     "moment of rotation. If they are, an attacker with the old keys could "
     "race the legitimate user and publish a fake rotation announcement to "
     "hijack the relationship. This limitation is documented; the right "
     "response to suspected compromise is to use full account recovery via "
     "the phrase, which rebuilds the identity independently of the old "
     "credentials. Future hardening (a separate rotation key derived from "
     "the recovery phrase) is on the roadmap."),

    # ============ SESSION PERSISTENCE ============
    ('h1', '9. Session persistence'),
    ('p',
     "By default a logged-in Tarn client holds its derived keys — signing "
     "keypair, unwrapped DEK chain, sharing keypair, JWT — in memory only. "
     "When the page closes, the keys are gone, and the next session requires "
     "re-deriving from email + password (paying the full Argon2id cost). For "
     "consumer apps this is a UX floor that's hard to ship below."),
    ('p',
     "Tarn provides an <i>opt-in</i> session-persistence primitive: apps that "
     "want it can serialize a logged-in client to an opaque blob, store the "
     "blob in <code>localStorage</code>, and resume from it on a later page "
     "load without prompting the user for their password. The default "
     "behaviour (no persistence) is unchanged; apps with stricter postures "
     "stay opted out."),
    ('h2', 'At-rest encryption'),
    ('p',
     "The serialized session is encrypted under an AES-256-GCM wrapping key "
     "stored in IndexedDB with <code>extractable: false</code>. The "
     "non-extractable flag is the load-bearing piece of the threat model: "
     "even an attacker with code execution on the origin (XSS) cannot "
     "exfiltrate the raw key bytes for offline replay on another device — "
     "they can only invoke the key in-page, and only while they hold "
     "execution. The persisted blob is unreadable off-origin."),
    ('h2', 'Threat model and trade-offs'),
    ('p',
     "Persisting derived keys to client-side storage is a meaningful change "
     "to Tarn's threat surface, and Tarn is honest about it. Without "
     "persistence, a same-origin XSS can act as the user only while the page "
     "is open. With persistence, the same XSS gains pseudo-persistent access: "
     "it can decrypt the persisted blob in-page and act as the user up to "
     "the blob's expiry."),
    ('p',
     "Three constraints bound this risk:"),
    ('b',
     "<b>Hard 7-day max age</b>, baked into the blob at creation. The SDK "
     "does not refresh expiry on use; a quiet exfil-and-replay attack is "
     "bounded to one week regardless of activity."),
    ('b',
     "<b>Origin binding via the non-extractable wrapping key.</b> Stealing "
     "the persisted blob is useless without simultaneous code execution on "
     "the origin."),
    ('b',
     "<b>Automatic invalidation on key rotation.</b> Credential change, "
     "account recovery, and account deletion each rotate the wrapping key "
     "as a side effect, rendering all previously-emitted blobs on the origin "
     "unreadable."),
    ('p',
     "Apps with stricter threat models (financial, medical, etc.) should "
     "simply not opt in. The default constructor + <code>login()</code> "
     "path persists nothing."),
    ('h2', 'What gets persisted'),
    ('p',
     "Just enough to reconstitute the in-memory client without re-deriving "
     "from password: the signing keypair (PKCS#8 + SPKI), the unwrapped DEK "
     "chain (raw bytes per generation), the sharing keypair, the data and "
     "credential lookup keys, the recovery-factor metadata used by "
     "<code>changeCredentials</code>, and the current JWT. The "
     "credential_encryption_key is intentionally omitted — once the DEK "
     "chain is unwrapped at login, the KEK is dead state. Share-log caches "
     "are not persisted; they re-hydrate from Arweave on first use."),
    ('h2', 'Server-side session management'),
    ('p',
     "Section 7 (above) covers persistence — keeping a logged-in client "
     "alive across page reloads on a single device. Section 7.5 covers "
     "the complementary capability across devices: <i>multi-device session "
     "management</i> — letting a user list active sessions and revoke any "
     "of them individually without performing a full credential change."),
    ('p',
     "Shape:"),
    ('b',
     "<b>Per-session identifier.</b> Every successful "
     "<code>/auth/verify</code> issues a JWT carrying a <code>sid</code> "
     "claim — a fresh UUID. The server records the session in a new D1 "
     "<code>sessions</code> table with <code>created_at</code>, "
     "<code>last_seen_at</code>, and an optional device label."),
    ('b',
     "<b>Revocation endpoints.</b> <code>DELETE /api/v1/sessions/:sid</code> "
     "kills one session; <code>DELETE /api/v1/sessions</code> kills all "
     "active sessions for the user. Both require a valid JWT from any "
     "session belonging to the same account."),
    ('b',
     "<b>Listing endpoint.</b> <code>GET /api/v1/sessions</code> returns "
     "the user's active sessions so an app can render a "
     "<i>Manage devices</i> page."),
    ('b',
     "<b>Stateful auth middleware.</b> Authenticated request handling "
     "consults the <code>sessions</code> table to confirm the JWT's "
     "<code>sid</code> is still active. The added D1 lookup is mitigated "
     "by a short in-Worker cache to avoid hot-pathing the database."),
    ('p',
     "Together, persistence (Section 7) and session management "
     "(Section 7.5) close the consumer-app session story: users stay "
     "logged in across reloads on the devices they trust, and can kill "
     "individual sessions cleanly when they don't. <code>changeCredentials</code> "
     "remains available as a heavy-hammer alternative — it rotates the "
     "signing key and locks out every other device by force — but for "
     "routine device management the granular revoke endpoints are the "
     "right tool."),

    # ============ INVITE TOKENS ============
    ('h1', '10. Invite tokens'),
    ('p',
     "Section 7 (sharing) lets two users form an end-to-end-encrypted "
     "connection if and only if the sender knows the recipient's email and "
     "the recipient is already a Tarn user with discoverability enabled. "
     "For consumer apps the prevailing UX is the inverse: scan a QR, click "
     "a link in a messenger, register-then-redeem. Section 10 adds an "
     "<b>opaque, single-use, time-limited invite token</b> primitive that "
     "lets the inviter publish a redemption slot without knowing the "
     "recipient's identity, and lets the recipient redeem it (potentially "
     "after signing up) without ever transmitting the inviter's identifier "
     "through the channel that carried the link."),
    ('h2', 'Why server-mediated'),
    ('p',
     "Three alternative shapes were considered and rejected:"),
    ('b',
     "<b>Stateless QR / link.</b> Keys baked into the URL, no server "
     "state. Loses single-use; a leaked link in any messenger channel "
     "exposes the inviter to arbitrary stranger redemption forever."),
    ('b',
     "<b>Pure-Arweave invite blob.</b> Inviter publishes an Arweave entry; "
     "recipient reads it and sends a normal connection request. Single-use "
     "cannot be enforced at the storage layer; app-side single-use races "
     "between the legitimate recipient and any malicious party that "
     "scrapes the link."),
    ('b',
     "<b>Reuse the existing inbox-tag mechanism.</b> The inbox is "
     "share_pub-keyed and time-windowed; an anonymous inbox without a "
     "share_pub doesn't fit the model, and we'd be inventing single-use "
     "semantics on a primitive that doesn't want them."),
    ('p',
     "All three lose the atomic single-use property that only the server "
     "can provide cheaply. Section 10 is server-mediated for that reason "
     "alone — every other piece of the flow is client-side cryptography "
     "over an opaque blob."),
    ('h2', 'Cryptographic shape'),
    ('p',
     "The inviter generates two independent 32-byte secrets client-side: "
     "<code>token_id</code> (the opaque server-side index) and "
     "<code>payload_key</code> (the AES-256-GCM key that encrypts the "
     "invite payload). The payload contains the inviter's "
     "<code>share_pub</code>, <code>signing_pub</code>, "
     "<code>display_name</code>, app id, and timestamp. The "
     "<code>token_id</code> goes in the URL path; the "
     "<code>payload_key</code> goes in the URL fragment, which browsers "
     "do not include in HTTP requests."),
    ('p',
     "The Tarn API stores opaque ciphertext keyed on <code>token_id</code> "
     "and never sees the inviter's keys, name, or any other payload field. "
     "The recipient retrieves the ciphertext via an unauthenticated "
     "<code>GET /api/v1/invite/:token_id</code> for preview, decrypts "
     "client-side with the URL-fragment key, and then redeems via an "
     "authenticated <code>POST /api/v1/invite/redeem/:token_id</code> "
     "that atomically marks the token used. Both endpoints rate-limit "
     "via the existing primitives — D1-atomic for create/redeem (per "
     "account, per hour), KV-based for preview (per IP)."),
    ('h2', 'No Tarn-hosted landing page'),
    ('p',
     "Apps own the URL surface. Each registered app records an "
     "<code>invite_url_template</code> (e.g. "
     "<code>https://app.bookish.example/invite/{token_id}</code>); the "
     "SDK substitutes <code>{token_id}</code> and appends the URL "
     "fragment. The app's web handler reads the path + hash, calls the "
     "SDK, and renders whatever UX it wants — modal, toast, native "
     "deep-link. Tarn does not host any landing page. Messenger preview "
     "unfurls and install fallbacks are the app's responsibility."),
    ('h2', 'Composes with existing connection primitives'),
    ('p',
     "After redeeming, the recipient's SDK sends a normal connection-"
     "request HPKE-sealed back to the inviter using the keys retrieved "
     "from the decrypted payload. The request carries an extra "
     "<code>via_invite_token</code> field. The inviter's SDK, on its next "
     "<code>listIncomingRequests</code> poll, reads its issued-invites "
     "blob fresh and auto-accepts requests whose token matches a known "
     "issuance. Unmatched requests stay in the pending list for the user "
     "to act on. The end state is identical to a connection formed via "
     "email handshake — same connection record, same share-log mechanics, "
     "same mute and revoke primitives."),
    ('p',
     "Section 10 also wires up <code>Connection.label</code> as a real "
     "primitive — previously documented as an optional field but never "
     "implemented. Invite redemption seeds the new connection's label "
     "from the inviter's <code>display_name</code>, so apps get an "
     "out-of-the-box <i>This is Maya</i> tag without app-layer storage. "
     "Apps can also set or update labels manually via "
     "<code>setConnectionLabel</code>."),
    ('h2', 'Threat model'),
    ('p',
     "The dominant risk is a leaked link (screenshot, accidental Slack "
     "post). Mitigations: 7-day default expiry, hard 30-day max, single-"
     "use, and a sender-visible fingerprint of the redeemer's "
     "<code>share_pub</code> so the inviter can detect surprise "
     "redemption and revoke + reissue. A server compromise lets an "
     "attacker enumerate live tokens but not decrypt payloads — the "
     "decryption keys are URL fragments held only by recipients."),
    ('p',
     "The server learns metadata: which account issued an invite, the "
     "time of issuance, the time and originating IP of redemption, and "
     "the redeemer's <code>share_pub</code> fingerprint. It does not "
     "learn the inviter's <code>share_pub</code>, signing public key, "
     "display name, or any payload contents — those are inside the "
     "encrypted blob keyed by a secret the server never sees. This is "
     "the same zero-knowledge story as the rest of the protocol."),

    # ============ DEFERRED ============
    ('h1', '11. Deferred features'),
    ('p',
     "Several capabilities are intentionally deferred from the v1 platform. "
     "They are documented here so that future evolution paths are visible."),
    ('h3', 'Public broadcast / influencer scale'),
    ('p',
     "The current per-pair pattern strains around hundreds of connections per "
     "user. For applications that want public profiles where anyone can "
     "subscribe without approval, a separate broadcast primitive — single "
     "publish, fan-out reads — would be added. The cryptographic shape is "
     "different (publicly-readable signed content rather than per-recipient "
     "encryption); both can coexist in the same Tarn account."),
    ('h3', 'Hardened rotation under compromised keys'),
    ('p',
     "A separate rotation signing key derived from the recovery phrase (and "
     "thus independent of the master key) would close the §8 limitation. "
     "Adds modest complexity; not v1."),
    ('h3', 'Forward secrecy on sharing'),
    ('p',
     "Signal-style prekey bundles would give per-message forward secrecy "
     "for share-log entries, so that a future compromise of the recipient's "
     "key cannot decrypt past traffic. Achievable Arweave-native; complex; "
     "deferred until a use case demands it."),
    ('h3', 'Decoy traffic for stronger metadata privacy'),
    ('p',
     "Padding share log writes with decoy entries would obscure inferences "
     "from observable wrapping patterns. Substantial cost for marginal "
     "improvement; deferred."),

    # ============ GLOSSARY ============
    ('h1', '12. Glossary'),
    ('table',
     ['Term', 'Meaning'],
     [
         ['DEK', 'Data Encryption Key. Per-user, randomly generated, wraps per-content CEKs. Generation-indexed.'],
         ['CEK', 'Content Encryption Key. Per-blob, randomly generated, used once. Stable across versions of the same content item.'],
         ['KEK', 'Key Encryption Key. Derived from password (or recovery phrase). Wraps the DEK chain.'],
         ['Argon2id', 'Memory-hard password-based KDF. Used for password → master_key.'],
         ['HKDF', 'Hash-based Key Derivation Function (RFC 5869). Used to expand master_key into all sub-keys.'],
         ['HPKE', 'Hybrid Public-Key Encryption (RFC 9180). Used for connection-handshake bootstrap.'],
         ['X25519', 'Elliptic curve Diffie-Hellman over Curve25519. Used for sharing keypair and per-pair shared secrets.'],
         ['Connection', 'A mutual cryptographic relationship between two users. Apps may present this as friend/follow/contact/etc.'],
         ['Share log', 'Per-pair append-only stream of share operations. Stealth-addressed. Encrypted under per-pair K_AB.'],
         ['Stealth address', 'Tag derived via HMAC under a per-pair secret. Unlinkable to outside observers.'],
         ['Recovery phrase', '24-word BIP39 mnemonic generated client-side at signup. Independent access path to the DEK chain.'],
     ]),

    # ============ POINTERS ============
    ('h1', '13. Where to learn more'),
    ('p',
     "<b>Protocol specification.</b> The canonical reference is "
     "<code>docs/TARN_PROTOCOL.md</code> in the Tarn repository — full "
     "key-derivation derivations, blob formats, API surface, and rotation "
     "flows."),
    ('p',
     "<b>SDK reference.</b> The client SDK's README "
     "(<code>client/README.md</code>) covers the JavaScript API surface with "
     "examples: register, login, recovery, content CRUD, connection lifecycle, "
     "sharing primitives, mute filter."),
    ('p',
     "<b>Design history.</b> The two design notes "
     "(<code>2026-04-28-tarn-account-and-data-model.md</code> and "
     "<code>2026-04-28-tarn-sharing-design.md</code>) captured the design "
     "rationale during the build. They are useful reading for understanding "
     "<i>why</i> certain decisions were made — particularly the trade-offs "
     "around revocation, metadata privacy, and recovery."),
    ('p',
     "<b>Implementation history.</b> Issues 9–22 on the Tarn repository, "
     "filed and closed during the platform build, document the unit of work "
     "for each protocol section. Each closing comment serves as a self-"
     "contained record of what shipped under that section."),
]


# ============ DOCUMENT BUILDER ============

def render_cover(styles, story):
    """Cover page."""
    story.append(Spacer(1, 2.4 * inch))
    story.append(Paragraph('Tarn', styles['Title']))
    story.append(Paragraph('Architecture Guide', styles['Subtitle']))
    story.append(Paragraph(
        'Permanent, encrypted, user-owned data infrastructure',
        styles['Tagline'],
    ))
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph(date.today().strftime('%B %Y'), styles['Date']))
    story.append(PageBreak())


def render_toc(styles, story):
    """Static table of contents derived from CONTENT."""
    story.append(Paragraph('Contents', styles['H1']))
    for entry in CONTENT:
        if entry[0] == 'h1':
            story.append(Paragraph(entry[1], styles['TocEntry']))
        elif entry[0] == 'h2':
            story.append(Paragraph(entry[1], styles['TocSub']))
    story.append(PageBreak())


def render_content(styles, story):
    """Render the CONTENT list into Platypus flowables."""
    for entry in CONTENT:
        kind = entry[0]
        if kind == 'h1':
            story.append(Paragraph(entry[1], styles['H1']))
        elif kind == 'h2':
            story.append(Paragraph(entry[1], styles['H2']))
        elif kind == 'h3':
            story.append(Paragraph(entry[1], styles['H3']))
        elif kind == 'p':
            story.append(Paragraph(entry[1], styles['Body']))
        elif kind == 'b':
            story.append(Paragraph(f'• {entry[1]}', styles['Bullet']))
        elif kind == 'code':
            story.append(Preformatted(entry[1], styles['Code']))
        elif kind == 'callout':
            story.append(Paragraph(f'<i>— {entry[1]}</i>', styles['Callout']))
        elif kind == 'spacer':
            story.append(Spacer(1, 0.2 * inch))
        elif kind == 'pagebreak':
            story.append(PageBreak())
        elif kind == 'table':
            _, headers, rows = entry
            data = [headers] + rows
            tbl = Table(data, colWidths=[1.4 * inch, 5.0 * inch])
            tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2c5f2d')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 9.5),
                ('LEADING', (0, 0), (-1, -1), 13),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1a1a1a')),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                    [colors.white, colors.HexColor('#f4f4f2')]),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.HexColor('#dcdcd5')),
            ]))
            story.append(Spacer(1, 0.1 * inch))
            story.append(tbl)
            story.append(Spacer(1, 0.15 * inch))


def make_page_template(styles):
    """Template with footer (page number + 'Tarn Architecture Guide')."""
    def draw_footer(canvas, doc):
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#6b6b6b'))
        canvas.drawCentredString(
            LETTER[0] / 2,
            0.5 * inch,
            f'Tarn Architecture Guide  ·  Page {doc.page}',
        )
        canvas.restoreState()

    frame = Frame(
        x1=1 * inch,
        y1=0.85 * inch,
        width=LETTER[0] - 2 * inch,
        height=LETTER[1] - 1.7 * inch,
        showBoundary=0,
    )
    return PageTemplate(id='main', frames=[frame], onPage=draw_footer)


def build(output_path: Path):
    styles = make_styles()
    doc = BaseDocTemplate(
        str(output_path),
        pagesize=LETTER,
        title='Tarn Architecture Guide',
        author='Tarn',
        subject='Architecture and design overview',
        leftMargin=1 * inch, rightMargin=1 * inch,
        topMargin=0.85 * inch, bottomMargin=0.85 * inch,
    )
    doc.addPageTemplates([make_page_template(styles)])

    story = []
    render_cover(styles, story)
    render_toc(styles, story)
    render_content(styles, story)

    doc.build(story)


if __name__ == '__main__':
    here = Path(__file__).resolve().parent
    out = here.parent / 'docs' / 'tarn-architecture-guide.pdf'
    out.parent.mkdir(parents=True, exist_ok=True)
    build(out)
    print(f'Wrote: {out}')
