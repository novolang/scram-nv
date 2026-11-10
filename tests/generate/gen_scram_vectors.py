# Writes ../scram_vectors_tests.nv: the SCRAM exchanges of RFC 5802 section 5
# and RFC 7677 section 3, read from the RFC text, and more exchanges computed
# by the reference below.
#
#   curl -sLo rfc5802.txt https://www.rfc-editor.org/rfc/rfc5802.txt
#   curl -sLo rfc7677.txt https://www.rfc-editor.org/rfc/rfc7677.txt
#   python3 -I gen_scram_vectors.py rfc5802.txt rfc7677.txt
#   novo fmt ../scram_vectors_tests.nv
#
# The reference is RFC 5802 section 3 written out over Python's hashlib
# (pbkdf2_hmac, hmac, sha1, sha256).  Before its output is used it must
# reproduce the two RFC exchanges exactly, and the script stops if it does not.
import base64
import hashlib
import hmac
import os
import sys


def b64(b):
    return base64.b64encode(b).decode()


def exchange(mech, user, pw, salt, iters, cnonce, snonce, authzid=None):
    name = {"SCRAM-SHA-1": "sha1", "SCRAM-SHA-256": "sha256"}[mech]
    h = getattr(hashlib, name)
    esc = lambda s: s.replace("=", "=3D").replace(",", "=2C")
    gs2 = "n,,"
    if authzid is not None:
        gs2 = "n,a=%s," % esc(authzid)
    bare = "n=%s,r=%s" % (esc(user), cnonce)
    nonce = cnonce + snonce
    s1 = "r=%s,s=%s,i=%d" % (nonce, b64(salt), iters)
    salted = hashlib.pbkdf2_hmac(name, pw.encode(), salt, iters)
    ck = hmac.new(salted, b"Client Key", h).digest()
    sk = h(ck).digest()
    sv = hmac.new(salted, b"Server Key", h).digest()
    cfw = "c=%s,r=%s" % (b64(gs2.encode()), nonce)
    auth = bare + "," + s1 + "," + cfw
    csig = hmac.new(sk, auth.encode(), h).digest()
    proof = bytes(a ^ b for a, b in zip(ck, csig))
    c2 = cfw + ",p=" + b64(proof)
    s2 = "v=" + b64(hmac.new(sv, auth.encode(), h).digest())
    stored = "%s$%d:%s$%s:%s" % (mech, iters, b64(salt), b64(sk), b64(sv))
    return gs2 + bare, s1, c2, s2, stored


def rfc_exchange(path, start):
    lines = open(path).read().split("\n")
    msgs = []
    i = start
    while len(msgs) < 4:
        l = lines[i]
        if l.startswith("   C: ") or l.startswith("   S: "):
            msgs.append(l[6:].strip())
        elif msgs and l.startswith("      ") and l.strip():
            msgs[-1] += l.strip()
        i += 1
    return msgs


def find(path, needle):
    lines = open(path).read().split("\n")
    return next(i for i, l in enumerate(lines) if needle in l)


def q(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


rfc5802, rfc7677 = sys.argv[1], sys.argv[2]
# RFC 5802 section 5: SCRAM-SHA-1, user "user", password "pencil".
e1 = rfc_exchange(rfc5802, find(rfc5802, "C: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL"))
# RFC 7677 section 3: SCRAM-SHA-256.
e2 = rfc_exchange(rfc7677, find(rfc7677, "C: n,,n=user,r=rOprNGfwEbeRWgbNEkqO"))

CASES = []


def rfc_case(label, mech, msgs, cnonce):
    s1 = msgs[1]
    nonce = s1.split(",")[0][2:]
    salt = base64.b64decode(s1.split(",")[1][2:])
    iters = int(s1.split(",")[2][2:])
    snonce = nonce[len(cnonce):]
    mine = exchange(mech, "user", "pencil", salt, iters, cnonce, snonce)
    assert list(mine[:4]) == msgs, (label, mine, msgs)
    CASES.append((label, mech, "user", "pencil", cnonce, snonce, salt, iters, None, mine))


rfc_case("RFC 5802 section 5", "SCRAM-SHA-1", e1, "fyko+d2lbbFgONRv9qkxdawL")
rfc_case("RFC 7677 section 3", "SCRAM-SHA-256", e2, "rOprNGfwEbeRWgbNEkqO")


def det(label, n):
    out = b""
    i = 0
    while len(out) < n:
        out += hashlib.sha256(label.encode() + i.to_bytes(4, "big")).digest()
        i += 1
    return out[:n]


EXTRA = [
    ("SHA-256, 4096 iterations", "SCRAM-SHA-256", "alice", "s3cr3t!", 4096, None),
    ("SHA-1, 4096 iterations", "SCRAM-SHA-1", "bob", "correct horse battery staple", 4096, None),
    ("SHA-256, a name with a comma and an equals sign", "SCRAM-SHA-256", "a,b=c", "pw", 4096, None),
    ("SHA-1, an authorization identity with a comma", "SCRAM-SHA-1", "user", "pencil", 4096, "admin,x=y"),
    ("SHA-256, one iteration", "SCRAM-SHA-256", "u", "p", 1, None),
    ("SHA-256, 15000 iterations and a long password", "SCRAM-SHA-256", "carol", "x" * 200, 15000, None),
    ("SHA-1, an empty password", "SCRAM-SHA-1", "dave", "", 4096, None),
]
for k, (label, mech, user, pw, iters, authzid) in enumerate(EXTRA):
    salt = det("salt%d" % k, 16)
    cnonce = b64(det("cnonce%d" % k, 18))
    snonce = b64(det("snonce%d" % k, 18))
    CASES.append((label, mech, user, pw, cnonce, snonce, salt, iters, authzid,
                  exchange(mech, user, pw, salt, iters, cnonce, snonce, authzid)))

HEAD = '''// scram_vectors_tests.nv — complete SCRAM exchanges.
//
// The first two are the examples of RFC 5802 section 5 (SCRAM-SHA-1) and
// RFC 7677 section 3 (SCRAM-SHA-256), cut out of the RFC text by
// tests/generate/gen_scram_vectors.py.  The others are computed by the
// reference in that script, RFC 5802 section 3 written out over Python's
// hashlib, which reproduces the two RFC exchanges byte for byte before it is
// used.  Nothing here was computed by this package.
//
// Each exchange is run from both ends.  The client makes the client-first
// message, answers the server-first message with the client-final message
// and accepts the server-final message.  The server reads the client-first
// message, answers the server-first message from a credential made from the
// password, accepts the client-final message and answers the server-final
// message.  The credential's text form is compared as well.

use std.test
use std.bytes
use scramerr
use scramcalc
use scramclient
use scramserver

fn mech_named(name: Str) -> ScramMech
    match scramcalc.mech_of_name(name)
        Ok(m)  => m
        Err(_) => ScramSha1

fn text(b: Bytes) -> Str
    bytes.to_str(b)

fn wire(s: Str) -> Bytes
    bytes.from_str(s)

fn check_exchange(label: Str, mech_name: Str, user: Str, password: Str, cnonce: Str, snonce: Str, salt64: Str,
                  iterations: Int, authzid: ?Str, c1: Str, s1: Str, c2: Str, s2: Str, stored_text: Str)
    test.case(label)
    let mech = mech_named(mech_name)
    let salt = bytes.from_base64(salt64) ?? bytes.zeros(0)
    let limits = ScramLimits { min_iterations: 1, max_iterations: 100000 }
    test.case("${label}: the client")
    match scramclient.client_first(mech, user, password, ScramPrepStrict, cnonce, authzid, limits)
        Err(_)    => test.fail("client_first refused")
        Ok(hello) =>
            test.assert_eq_str(text(hello.message), c1)
            match scramclient.client_final(hello.state, wire(s1))
                Err(_)    => test.fail("client_final refused")
                Ok(proof) =>
                    test.assert_eq_str(text(proof.message), c2)
                    match scramclient.client_finish(proof.state, wire(s2))
                        Err(_) => test.fail("the server's signature was refused")
                        Ok(_)  => test.assert_eq_str("done", "done")
    test.case("${label}: the server")
    match scramcalc.stored_from_password(mech, password, ScramPrepStrict, salt, iterations)
        Err(_)     => test.fail("stored_from_password refused")
        Ok(stored) =>
            test.assert_eq_str(scramcalc.stored_to_text(stored), stored_text)
            match scramserver.server_begin(wire(c1))
                Err(_)    => test.fail("server_begin refused")
                Ok(hello) =>
                    test.assert_eq_str(hello.username, user)
                    test.assert_eq(hello.authzid, authzid)
                    match scramserver.server_challenge(hello.state, stored, snonce)
                        Err(_)        => test.fail("server_challenge refused")
                        Ok(challenge) =>
                            test.assert_eq_str(text(challenge.message), s1)
                            match scramserver.server_verify(challenge.state, wire(c2))
                                Err(_)   => test.fail("the proof was refused")
                                Ok(done) => test.assert_eq_str(text(done.message), s2)
'''
out = [HEAD]
for n, (label, mech, user, pw, cnonce, snonce, salt, iters, authzid, m) in enumerate(CASES):
    out.append("\n@test\nfn test_exchange_%d() [io]\n" % n)
    az = "None" if authzid is None else "Some(%s)" % q(authzid)
    out.append("    check_exchange(%s, %s, %s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s)\n" % (
        q(label), q(mech), q(user), q(pw), q(cnonce), q(snonce), q(b64(salt)), iters, az,
        q(m[0]), q(m[1]), q(m[2]), q(m[3]), q(m[4])))
dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scram_vectors_tests.nv")
open(dest, "w").write("".join(out))
print("wrote", dest, len(CASES), "exchanges")
