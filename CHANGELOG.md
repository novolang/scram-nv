# Changelog

All notable changes to scram-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.1.0

SASL SCRAM-SHA-1 and SCRAM-SHA-256 (RFC 5802, RFC 7677) and SASL PLAIN (RFC 4616).

### Added

- The client as `client_first`, `client_final` and `client_finish`, and the server as
  `server_begin`, `server_challenge` and `server_verify`, each state a value of its own type.
- The attribute grammar of the four messages, the name escaping and the nonce rule.
- The key chain of RFC 5802 section 3 over crypto-nv's HMAC and pbkdf2-nv.
- `ScramStored`, the credential a server keeps, and its text form
  `SCRAM-SHA-256$4096:<salt>$<StoredKey>:<ServerKey>` (RFC 5803).
- Iteration limits for the client, and password preparation as `ScramPrepStrict` or
  `ScramPrepVerbatim`.
- SASL PLAIN as `plain_message` and `plain_parse`.
- Tests: the examples of RFC 5802 and RFC 7677 from the RFC text, seven more exchanges from an
  independent reference, RFC 4616's examples and the refusals.

### Known

- Channel binding is not implemented: the `-PLUS` mechanisms and the `p=` flag are refused.
- SASLprep normalization is not implemented. A password with a byte beyond ASCII is refused
  under `ScramPrepStrict` and sent as typed under `ScramPrepVerbatim`.
- SCRAM-SHA-512 and the other hashes of RFC 7804 and the IANA registry are not implemented.

This release requires novo 0.23.0 or later.
