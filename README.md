# scram-nv

The Salted Challenge Response Authentication Mechanism (SCRAM) lets a client
prove that it knows a password without sending it, and lets the server prove
the same to the client. It is specified in
[RFC 5802](https://www.rfc-editor.org/rfc/rfc5802), and
[RFC 7677](https://www.rfc-editor.org/rfc/rfc7677) adds SCRAM-SHA-256. It is the
login of PostgreSQL, MongoDB, Kafka, XMPP and many LDAP and mail servers. This
package brings it to novo-lang as two state machines that the caller drives, and
adds SASL PLAIN ([RFC 4616](https://www.rfc-editor.org/rfc/rfc4616)), the mechanism
every server that offers SCRAM also offers. It uses the HMAC and hashes of
[crypto-nv](https://novo-lang.org/packages/crypto-nv) and the key derivation of
[pbkdf2-nv](https://novo-lang.org/packages/pbkdf2-nv).

## What SCRAM is

SCRAM is a SASL mechanism: a short exchange of messages inside a protocol that
has a place for one, such as the PostgreSQL startup or a Kafka `SaslAuthenticate`
request. The server stores, for each user, a **salt**, an **iteration count** and
two keys derived from the password. It never stores the password.

The exchange has four messages (RFC 5802 section 5).

1. **client-first**: the user name and a random **client nonce**.
2. **server-first**: the client nonce followed by the server's own nonce, the
   user's salt and the iteration count.
3. **client-final**: the same combined nonce and the **client proof**.
4. **server-final**: the **server signature**.

Each message is a line of attributes separated by commas, each a letter, an equals
sign and a value. Both ends compute the following (RFC 5802 section 3), with `H` the
mechanism's hash and `Hi` PBKDF2 over the matching HMAC.

```
SaltedPassword  := Hi(password, salt, iterations)
ClientKey       := HMAC(SaltedPassword, "Client Key")
StoredKey       := H(ClientKey)
ServerKey       := HMAC(SaltedPassword, "Server Key")
AuthMessage     := client-first-bare "," server-first "," client-final-without-proof
ClientProof     := ClientKey XOR HMAC(StoredKey, AuthMessage)
ServerSignature := HMAC(ServerKey, AuthMessage)
```

The server checks the proof by recovering `ClientKey` from it and comparing `H` of
that with the `StoredKey` it holds. The client checks the server by comparing the
signature, which only a holder of `ServerKey` can compute. The nonces make every
exchange different, so a recorded one cannot be replayed.

The mechanisms differ in the hash: SCRAM-SHA-1 uses SHA-1 and 20-byte keys, and
SCRAM-SHA-256 uses SHA-256 and 32-byte keys.

## Install

```
novo pkg add scram-nv
```

## Example

```novo
use std.bytes
use scramcalc
use scramclient

// The client side of a login.  `nonce` is 18 or more random bytes written as
// printable ASCII, new for each attempt.  The caller sends `hello.message`,
// reads the server's reply, and calls `client_final` with it.
fn first_message(user: Str, password: Str, nonce: Str) -> Str
    match scramclient.client_first(ScramSha256, user, password, ScramPrepStrict, nonce, None, scramcalc.default_limits())
        Err(e)    => e.message()
        Ok(hello) => bytes.to_str(hello.message)
```

Build and test with:

```
novo pkg build               # type- and effect-check the package
novo test tests --isolate    # RFC 5802, RFC 7677, RFC 4616 and the refusals
```

## What the package contains

| Module | Contents |
| --- | --- |
| `scramclient` | The client: `client_first`, `client_final` and `client_finish`, and the states between them. |
| `scramserver` | The server: `server_begin`, `server_challenge` and `server_verify`, `server_error_message`, and the states between them. |
| `scramcalc` | The mechanisms and the arithmetic of SCRAM, password preparation, the iteration limits, and `ScramStored`, the credential a server keeps, with its text form. |
| `scramwire` | The four messages read into their parts, the name escaping and the nonce rule. |
| `saslplain` | SASL PLAIN: `plain_message` for a client and `plain_parse` for a server. |
| `scramerr` | The error type `ScramError`. |

No function reads a clock, draws randomness, opens a connection or performs input or output.

## How to choose an entry point

**A client calls `scramclient`.** Pick the mechanism with `scramcalc.choose_mechanism` from
the list the server offered. Call `client_first` and send the message. Pass the server's
reply to `client_final` and send the answer. Pass the server's last message to
`client_finish`. Each call returns the next state, so the steps cannot be taken out of order.

**A server calls `scramserver`.** `server_begin` reads the client's first message and
answers the user name. The server looks that user up and passes the user's `ScramStored` to
`server_challenge`. `server_verify` checks the proof. When it refuses, the server sends
`server_error_message` and closes the exchange.

**A server makes credentials with `scramcalc.stored_from_password`**, stores them with
`stored_to_text`, and reads them back with `stored_from_text`.

**A client that is offered only PLAIN calls `saslplain.plain_message`.** It sends the
password itself and belongs inside a protected channel.

## The rules a user needs

1. **The nonces are the caller's.** Both are printable ASCII without a comma, from a
   cryptographically secure generator, new for every exchange. This package draws no random
   numbers. A repeated client nonce lets a recorded exchange be replayed. RFC 5802 section 5.1.
2. **The client checks the server's nonce.** The combined nonce must begin with the client's
   and be longer. Otherwise the answer is `ScramNonceMismatch`.
3. **The iteration count comes from the server and is limited.** A `ScramLimits` gives the
   least and the most the client accepts. The default is 4096 to 10 million: 4096 is the least
   RFC 5802 section 5.1 says a server should announce, and a ceiling stops a hostile server from
   making the client compute for hours.
4. **The server's signature is checked.** `client_finish` compares it in constant time. A
   server that does not hold the credentials cannot produce it, and the answer is
   `ScramServerSignatureMismatch`.
5. **The password is prepared by `ScramPrep`.** RFC 5802 requires SASLprep (RFC 4013). The
   Unicode tables for it are not implemented. `ScramPrepStrict` accepts ASCII without control
   characters, for which it is exactly SASLprep, and refuses anything else. `ScramPrepVerbatim`
   sends the bytes as typed, as PostgreSQL does; a password that SASLprep would have rewritten
   then gives different keys from a peer that rewrote it.
6. **A user name is escaped.** An equals sign is written `=3D` and a comma `=2C`. The name is
   sent as given and is not prepared.
7. **Channel binding is not implemented.** The names ending `-PLUS` and the `p=` flag are
   refused with `ScramChannelBindingUnsupported`. A client sends the flag `n`. A server
   accepts `n` and `y`.
8. **A mandatory extension is refused.** An attribute `m=` where the grammar allows one is
   `ScramMandatoryExtension`. Other extensions are ignored.
9. **The server stores the stored key and the server key.** `ScramStored` holds them with the
   salt and the iteration count. They are enough to check a proof and not enough to compute
   one. Whoever reads them can guess passwords offline at the cost of the iteration count a
   guess, and can pose as the server to that user's client. The salt is random, new for each user.
10. **An unknown user gets a challenge too.** If a server answers an unknown name differently
    from a known one, a caller learns which names exist. The server derives a credential for the
    unknown name from a secret and a fixed iteration count, and runs the exchange to its end.
11. **A failed proof is `ScramProofMismatch` and nothing more.** A proof of the wrong length and
    one of the wrong value give the same answer.

## Timing behaviour

- The proof, the server signature and the stored key are compared in constant time, with
  crypto-nv's `digest.ct_eq`.
- Key derivation takes time proportional to the iteration count, which the server chooses.
- The password is held as bytes in the client state until the state is dropped.

## What is not included

- **Channel binding**, the `-PLUS` mechanisms and `tls-unique`, `tls-server-end-point` and
  `tls-exporter`. They need the TLS session's binding data. A caller that needs them cannot use
  this package for the `-PLUS` exchange.
- **SASLprep normalization.** See rule 5.
- **SCRAM-SHA-512 and SCRAM-SHA-224, SCRAM-SHA3-512** (RFC 7804 and the IANA registry). Kafka and
  MongoDB servers offer SCRAM-SHA-512.
- **The transport.** The messages are bytes. How they are carried, in a PostgreSQL
  `SASLInitialResponse`, a Kafka `SaslAuthenticate` request or a line of XMPP, is the caller's.
- **A random number generator.** See rule 1.
- **UTF-8 validation** of a PLAIN message's fields.

## Related packages

- [pbkdf2-nv](https://novo-lang.org/packages/pbkdf2-nv) supplies `Hi`.
- [crypto-nv](https://novo-lang.org/packages/crypto-nv) supplies HMAC, SHA-1 and SHA-256 and the
  constant-time comparison.
- [postgres-nv](https://novo-lang.org/packages/postgres-nv) has its own SCRAM-SHA-256 client in
  `pgauth`, including channel binding. Its non-PLUS path is the client of this package.
  [mysql-nv](https://novo-lang.org/packages/mysql-nv) has no SCRAM exchange: MySQL and MariaDB
  authenticate with `caching_sha2_password` and `mysql_native_password`.
  [kafka-nv](https://novo-lang.org/packages/kafka-nv) has no SASL yet; PLAIN and SCRAM-SHA-256
  are what this package gives it.

## Tests

`tests/scram_vectors_tests.nv` runs complete exchanges from both ends. The first two are the
examples of RFC 5802 section 5 (SCRAM-SHA-1) and RFC 7677 section 3 (SCRAM-SHA-256), cut out
of the RFC text by `tests/generate/gen_scram_vectors.py`. The others are computed by that
script's reference, RFC 5802 section 3 over Python's `hashlib`, which reproduces the two RFC
exchanges byte for byte before it is used. They include a name with a comma and an equals sign,
an authorization identity, one iteration, 15000 iterations and an empty password. Each also
checks the credential's text form.

`tests/plain_tests.nv` holds the two messages of RFC 4616 section 4. `tests/scram_edge_tests.nv`
covers the refusals: every malformed message, a server that answers `e=`, a nonce that is not
extended, iteration counts at each side of the limits, a proof from the wrong password and the
channel-binding names.

## Licence

Apache-2.0. See `LICENSE`.
