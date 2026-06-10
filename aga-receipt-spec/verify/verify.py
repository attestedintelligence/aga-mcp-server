#!/usr/bin/env python3
"""
Standalone SOUND verifier for the canonical AGA SEP Evidence Bundle.

Normative mirror of aga-receipt-spec/verify/verify-sep.mjs (CANONICAL_CONSTRUCTION_v2 §6).
Implements §6.1 structural floor, §6.2 receipt Ed25519 signatures, §6.3 chain linkage +
non-decreasing timestamps, §6.4 Merkle recomputation + index bijection, §6.5 mandatory
signed checkpoint, §6.6 provenance (only when a key is pinned).

Ed25519 verification uses an AUDITED library by DEFAULT (`cryptography`, then PyNaCl) — the
cross-stack soundness argument is "any trusted crypto library reproduces the verdict." A pure
stdlib RFC-8032 §5.1.7 implementation is included only as an explicit, zero-dependency
DEMONSTRATOR (opt in with `--ed25519 stdlib` or AGA_VERIFY_ED25519=stdlib); it must agree with
the audited path on the whole corpus. Hashing is stdlib (hashlib); small-order / non-canonical
public keys are rejected.

Library:  from verify_sep import verify_sep_bundle
CLI:      python verify_sep.py <bundle.json> [--pubkey <64-hex>] [--ed25519 stdlib]
          prints PASS/FAIL per step + "VERIFIED"/"FAILED"; exits 0 on VERIFIED, 1 on FAILED.
"""
import hashlib
import json
import math
import re
import sys

ALGO = "Ed25519-SHA256-JCS"
MAX_CANON_DEPTH = 100

# The EXACT canonical field set of a signed SEP receipt (strict-schema floor): exactly these 15
# keys — no more, no less — which rejects extra/unknown-field injection and "__proto__" injection.
RECEIPT_FIELDS = (
    "receipt_id", "receipt_version", "algorithm", "timestamp", "request_id",
    "method", "tool_name", "decision", "reason", "policy_reference",
    "arguments_hash", "previous_receipt_hash", "gateway_id", "public_key", "signature",
)

# The EXACT canonical field set of a signed SEP checkpoint (strict-schema floor): exactly these 7 keys.
CHECKPOINT_FIELDS = (
    "algorithm", "gateway_id", "generated_at", "head_leaf_hash", "leaf_count", "merkle_root", "signature",
)

# ---------------------------------------------------------------------------
# Canonicalization (byte-identical to the reference `canon`):
#   - objects: sort keys lexicographically, emit {"k":v,...} by string concat
#   - arrays:  preserve order
#   - scalars: JSON encoding without HTML-escaping (json.dumps default does not
#     HTML-escape). SEP receipt/checkpoint fields are ASCII; ensure_ascii=False
#     keeps any non-ASCII byte-for-byte identical to JS JSON.stringify.
# ---------------------------------------------------------------------------
def _dump_scalar(x):
    # Matches JS JSON.stringify for null/bool/number/string within the SEP field set.
    #
    # JCS / RFC 8785 number normalization (T2): an INTEGRAL float must serialize as its shortest
    # INTEGER form ("2", never "2.0"/"2e0"/"2.0e0"), matching json.dumps of an int and JS's
    # JSON.stringify(2.0) === "2". json.dumps(2.0) would emit "2.0", so coerce integral floats to
    # int first. (bool is a subclass of int but is handled by json.dumps directly; exclude it.)
    if isinstance(x, float) and not isinstance(x, bool):
        if x == int(x) and x not in (float("inf"), float("-inf")) and x == x:
            x = int(x)
    return json.dumps(x, ensure_ascii=False, separators=(",", ":"))


def canon(o):
    # Depth-bounded (anti-DoS): input nested beyond MAX_CANON_DEPTH raises a CONTROLLED error
    # well before a Python RecursionError, so verify can fail closed instead of crashing.
    # Mirrors canonical.ts (throws at depth > 100).
    def rec(o, depth):
        if depth > MAX_CANON_DEPTH:
            raise ValueError("canon: input nesting exceeds %d levels" % MAX_CANON_DEPTH)
        if o is None or isinstance(o, (bool, int, float, str)):
            return _dump_scalar(o)
        if isinstance(o, list):
            return "[" + ",".join(rec(v, depth + 1) for v in o) + "]"
        if isinstance(o, dict):
            return "{" + ",".join(
                _dump_scalar(k) + ":" + rec(o[k], depth + 1) for k in sorted(o.keys())
            ) + "}"
        raise TypeError("uncanonicalizable type: %r" % type(o))
    return rec(o, 0)


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def _u8(s):
    return s.encode("utf-8")


def leaf(receipt):
    # §3: leaf = sha256(utf8(canon(full receipt))), NO prefix.
    return sha256_hex(_u8(canon(receipt)))


def node(left_hex, right_hex):
    # §5: node = sha256(rawbytes(left) || rawbytes(right)).
    return sha256_hex(bytes.fromhex(left_hex) + bytes.fromhex(right_hex))


def strip(obj, field):
    return {k: v for k, v in obj.items() if k != field}


def has_exact_keys(o, fields):
    """Strict-schema floor: the object must carry EXACTLY the canonical fields — no extra,
    missing, renamed, duplicate, or "__proto__"-injected key. A JSON-parsed "__proto__" is an
    ordinary dict key in Python, so a 16th key fails the count. Mirrors hasExactKeys in verify.ts.
    """
    if not isinstance(o, dict):
        return False
    return len(o) == len(fields) and all(f in o for f in fields)


def is_hex(s, n):
    return isinstance(s, str) and re.fullmatch(r"[0-9a-f]{%d}" % n, s) is not None


def _as_index(x, n):
    """T3: normalize a JSON leaf_index to an int in [0, n), accepting an INTEGRAL float (0.0 -> 0)
    to match JS Number.isInteger(0.0) === true and Go. Returns the int, or None for a non-integer
    (0.5), a bool, a non-number, or an out-of-range value."""
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        i = x
    elif isinstance(x, float):
        if x != x or x in (float("inf"), float("-inf")) or x != int(x):
            return None  # NaN/inf/genuinely fractional (0.5) => reject
        i = int(x)
    else:
        return None
    if 0 <= i < n:
        return i
    return None


def _count_equals(x, n):
    """T4: True iff numeric `x` equals integer `n` (2.0 == 2). Rejects bool and non-number so a
    JSON bool/string can't accidentally satisfy the checkpoint count binding."""
    if isinstance(x, bool):
        return False
    if isinstance(x, int):
        return x == n
    if isinstance(x, float):
        return x == x and x not in (float("inf"), float("-inf")) and x == n
    return False


# ---------------------------------------------------------------------------
# Pure-Python Ed25519 verification (RFC 8032 §5.1.7), no third-party imports.
# ---------------------------------------------------------------------------
_P = (1 << 255) - 19           # field prime 2^255 - 19
_L = (1 << 252) + 27742317777372353535851937790883648493  # group order
_D = (-121665 * pow(121666, _P - 2, _P)) % _P              # curve constant d
_I = pow(2, (_P - 1) // 4, _P)                             # sqrt(-1)


def _recover_x(y, sign):
    # Recover x-coordinate on the twisted Edwards curve for given y and sign bit.
    if y >= _P:
        return None
    xx = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        return None  # no square root: not a valid point
    if (x & 1) != sign:
        x = _P - x
    return x


# Edwards point addition in extended homogeneous coords (X, Y, Z, T), T = XY/Z.
def _edwards_add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = t1 * 2 * _D * t2 % _P
    d = z1 * 2 * z2 % _P
    e = b - a
    f = d - c
    g = d + c
    h = b + a
    x3 = e * f
    y3 = g * h
    t3 = e * h
    z3 = f * g
    return (x3 % _P, y3 % _P, z3 % _P, t3 % _P)


def _scalarmult(P, e):
    Q = (0, 1, 1, 0)  # neutral element
    while e > 0:
        if e & 1:
            Q = _edwards_add(Q, P)
        P = _edwards_add(P, P)
        e >>= 1
    return Q


def _point_equal(P, Q):
    x1, y1, z1, _ = P
    x2, y2, z2, _ = Q
    if (x1 * z2 - x2 * z1) % _P != 0:
        return False
    if (y1 * z2 - y2 * z1) % _P != 0:
        return False
    return True


# Base point B.
_BY = 4 * pow(5, _P - 2, _P) % _P
_BX = _recover_x(_BY, 0)
_B = (_BX % _P, _BY % _P, 1, _BX * _BY % _P)


def _decode_point(s):
    # s: 32 raw bytes. Returns extended point or None if invalid.
    y = int.from_bytes(s, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x % _P, y % _P, 1, (x * y) % _P)


def _ed25519_verify_stdlib(public_key_bytes, message, signature):
    """RFC 8032 §5.1.7 verify in PURE PYTHON (stdlib only).

    OPT-IN, zero-dependency DEMONSTRATOR — NOT the default. The cross-stack soundness
    argument is "any trusted, audited crypto library reproduces the verdict", which a
    hand-rolled implementation should not anchor; the default path is _ed25519_verify_audited.
    Enable this path with `--ed25519 stdlib` or AGA_VERIFY_ED25519=stdlib (it must agree with
    the audited path on the whole corpus — that is what the cross-stack harness checks).
    """
    if len(public_key_bytes) != 32 or len(signature) != 64:
        return False
    A = _decode_point(public_key_bytes)
    if A is None:
        return False
    R_bytes = signature[:32]
    R = _decode_point(R_bytes)
    if R is None:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= _L:
        return False  # non-canonical / out-of-range scalar
    h = int.from_bytes(
        hashlib.sha512(R_bytes + public_key_bytes + message).digest(), "little"
    ) % _L
    # Check [S]B == R + [h]A   (cofactorless verification per RFC 8032 §5.1.7).
    sB = _scalarmult(_B, S)
    hA = _scalarmult(A, h)
    rhs = _edwards_add(R, hA)
    return _point_equal(sB, rhs)


def _ed25519_verify_audited(public_key_bytes, message, signature):
    """DEFAULT verify path — an audited Ed25519 library (cryptography, then PyNaCl)."""
    if len(public_key_bytes) != 32 or len(signature) != 64:
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
        try:
            Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, message)
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    except ImportError:
        pass
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        try:
            VerifyKey(public_key_bytes).verify(message, signature)
            return True
        except BadSignatureError:
            return False
        except Exception:
            return False
    except ImportError:
        raise RuntimeError(
            "no audited Ed25519 library found (install `cryptography` or `pynacl`); "
            "or run the zero-dependency demonstrator with --ed25519 stdlib / AGA_VERIFY_ED25519=stdlib"
        )


def _stdlib_mode():
    import os
    return os.environ.get("AGA_VERIFY_ED25519", "").strip().lower() == "stdlib"


def _ed25519_verify(public_key_bytes, message, signature):
    """Dispatch to the DEFAULT audited library, or the opt-in pure-stdlib demonstrator."""
    if _stdlib_mode():
        return _ed25519_verify_stdlib(public_key_bytes, message, signature)
    return _ed25519_verify_audited(public_key_bytes, message, signature)


# ---------------------------------------------------------------------------
# Public-key well-formedness: small-order rejection + canonical-y check.
# Ed25519 points of order dividing 8 are trivially forgeable; reject them.
# ---------------------------------------------------------------------------
SMALL_ORDER_KEYS = frozenset([
    "00" * 32,
    "00" * 31 + "80",
    "01" + "00" * 31,
    "01" + "00" * 30 + "80",
    "ec" + "ff" * 30 + "7f",
    "ec" + "ff" * 31,
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
])


def _is_canonical_y(hex_key):
    # Decode y little-endian, clear the top sign bit, require y < p.
    b = bytes.fromhex(hex_key)
    y = 0
    for i in range(32):
        byte = (b[i] & 0x7F) if i == 31 else b[i]
        y |= byte << (8 * i)
    return y < _P


def well_formed_key(hex_key):
    if not is_hex(hex_key, 64):
        return False
    if hex_key in SMALL_ORDER_KEYS:
        return False
    if not _is_canonical_y(hex_key):
        return False
    # Must decode to a real curve point.
    return _decode_point(bytes.fromhex(hex_key)) is not None


def sig_ok(pub_hex, msg, sig_hex):
    if not well_formed_key(pub_hex):
        return False
    if not is_hex(sig_hex, 128):
        return False
    if re.fullmatch(r"0+", sig_hex):
        return False
    try:
        return _ed25519_verify(
            bytes.fromhex(pub_hex), _u8(msg), bytes.fromhex(sig_hex)
        )
    except Exception:
        return False


# ---------------------------------------------------------------------------
# §6 verification.
# ---------------------------------------------------------------------------
# Canonical SEP timestamp form (T1): exactly what Date.prototype.toISOString() emits —
# YYYY-MM-DDTHH:MM:SS.mmmZ. Validated by an EXACT regex (literal [0-9], NOT \d, because Python's
# \d matches Unicode decimal digits and would diverge from JS/Go) plus PURE-INTEGER calendar-range
# checks. NO date library (no datetime/fromisoformat/strptime) is used for validation or ordering.
_TS_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)


def _is_leap(y):
    return (y % 4 == 0) and ((y % 100 != 0) or (y % 400 == 0))


def _days_in_month(y, m):
    return [31, 29 if _is_leap(y) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1]


def _ts_valid(t):
    """True iff `t` is a canonical SEP timestamp: matches the exact fixed-width regex AND has
    in-range calendar fields, computed with pure integer arithmetic (no date library)."""
    if not isinstance(t, str):
        return False
    # fullmatch, NOT match: Python's re treats a single trailing "\n" as end-of-string for both
    # `$` and `.match()`, so `_TS_RE.match("...Z\n")` would WRONGLY accept a trailing-newline
    # timestamp that JS RegExp `$` and Go regexp `$` both reject — a cross-stack divergence.
    # fullmatch requires the ENTIRE string to match, rejecting any trailing byte identically.
    if _TS_RE.fullmatch(t) is None:
        return False
    year = int(t[0:4])
    month = int(t[5:7])
    day = int(t[8:10])
    hour = int(t[11:13])
    minute = int(t[14:16])
    second = int(t[17:19])
    if month < 1 or month > 12:
        return False
    if day < 1 or day > _days_in_month(year, month):
        return False
    if hour > 23:
        return False
    if minute > 59:
        return False
    if second > 59:
        return False
    return True


def _reject_nonfinite_json(token):
    # json.load passes the bare tokens 'Infinity', '-Infinity', 'NaN' here. RFC-8259 defines
    # no such literals; JS (JSON.parse) and Go (encoding/json) reject them at parse time. Without
    # this, a bundle carrying a non-finite token VERIFIES here while the other reference verifiers
    # FAIL it — a cross-stack verdict split. Raising makes the CLI parse fail closed, in agreement.
    raise ValueError("non-finite JSON constant %r is not valid RFC-8259 JSON" % (token,))


def _has_nonfinite(obj):
    # Defense in depth for LIBRARY callers that parsed with a lenient loader (Python's default
    # json.load ACCEPTS NaN/Infinity): a parsed value carrying a non-finite float is rejected so
    # verify_sep_bundle stays verdict-identical to the JS/Go reference verifiers.
    if isinstance(obj, float):
        return not math.isfinite(obj)
    if isinstance(obj, dict):
        return any(_has_nonfinite(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_nonfinite(v) for v in obj)
    return False


def verify_sep_bundle(bundle, expected_public_key=None):
    """Return dict: {verdict, issuerVerified, pinned, steps:[{name, ok}]}.

    verdict == 'VERIFIED' iff every step passed.

    Robust contract (D6): a malformed/hostile bundle (depth bomb, type confusion, missing
    structure, non-string where a string is expected) yields a FAILED verdict — NEVER a thrown
    exception / crash / RecursionError. Mirrors the try/catch in verify.ts.
    """
    pinned = is_hex(expected_public_key, 64)
    try:
        if _has_nonfinite(bundle):
            raise ValueError("bundle contains a non-finite JSON number (NaN/Infinity)")
        return _verify_sep_bundle_inner(bundle, expected_public_key, pinned)
    except Exception as e:  # noqa: BLE001 — fail closed on ANY error, including RecursionError.
        return {
            "verdict": "FAILED",
            "issuerVerified": False,
            "pinned": bool(pinned),
            "steps": [{"name": "verifier_exception", "ok": False}],
            "summary": "FAILED — verifier rejected a malformed bundle (%s)" % (e,),
        }


def _verify_sep_bundle_inner(bundle, expected_public_key, pinned):
    steps = []

    def add(name, ok):
        steps.append({"name": name, "ok": bool(ok)})
        return ok

    receipts = bundle.get("receipts") if isinstance(bundle, dict) else None
    receipts = receipts if isinstance(receipts, list) else []
    proofs = bundle.get("merkle_proofs") if isinstance(bundle, dict) else None
    proofs = proofs if isinstance(proofs, list) else []
    pub = bundle.get("public_key") if isinstance(bundle, dict) else None

    # §6.1 structural floor — incl. STRICT receipt schema (D1): exactly the 15 canonical fields;
    # rejects extra/unknown keys and "__proto__" injection on every signed receipt.
    add(
        "structural",
        isinstance(bundle, dict)
        and bundle.get("algorithm") == ALGO
        and well_formed_key(pub)
        and len(receipts) > 0
        and len(proofs) == len(receipts)
        and all(has_exact_keys(r, RECEIPT_FIELDS) for r in receipts),
    )

    # §6.2 receipt signatures
    add(
        "receipt_signatures",
        len(receipts) > 0
        and all(
            isinstance(r, dict)
            and sig_ok(pub, canon(strip(r, "signature")), r.get("signature"))
            for r in receipts
        ),
    )

    # §6.3 chain linkage + STRICT non-decreasing timestamps (D3, T1). Every receipt timestamp must
    # be the canonical SEP form (exact regex + pure-integer calendar range); an invalid timestamp =>
    # FAIL (incl. the first receipt). Because the form is fixed-width zero-padded UTC, ordering is a
    # PLAIN STRING (lexicographic) compare: ts[i] >= ts[i-1] (EQUAL allowed). No epoch/Date conversion.
    leaves = [leaf(r) for r in receipts]
    chain = len(receipts) > 0
    prev_ts = None  # first receipt only needs to be VALID; no prior to compare against
    for i in range(len(receipts)):
        expect_prev = "" if i == 0 else leaves[i - 1]
        if (receipts[i].get("previous_receipt_hash") or "") != expect_prev:
            chain = False
        ts = receipts[i].get("timestamp")
        if not _ts_valid(ts):
            chain = False  # invalid/non-canonical timestamp => fail (incl. the first receipt)
        else:
            if prev_ts is not None and ts < prev_ts:  # lexicographic string compare
                chain = False
            prev_ts = ts
    add("chain_and_ordering", chain)

    # §6.4 Merkle: recompute each leaf, walk siblings/directions, per-proof root (D4), single
    # root, bijection.
    root = None
    merkle = len(proofs) == len(receipts) and len(proofs) > 0
    seen = set()
    for p in proofs:
        if not isinstance(p, dict):
            merkle = False
            continue
        # T3: accept an INTEGRAL-float leaf_index (0.0 -> 0); reject non-integer/out-of-range/bool.
        idx = _as_index(p.get("leaf_index"), len(receipts))
        seen.add(idx)  # normalized int (0 and 0.0 collapse, so a dup index still fails bijection)
        recomputed = leaves[idx] if idx is not None else None
        if recomputed is None or recomputed != p.get("leaf_hash"):
            merkle = False
        cur = p.get("leaf_hash")
        siblings = p.get("siblings") or []
        directions = p.get("directions") or []
        if len(siblings) != len(directions):
            merkle = False
        ok_walk = True
        for j in range(len(siblings)):
            if not (is_hex(cur, 64) and is_hex(siblings[j], 64)):
                ok_walk = False
                break
            if directions[j] == "left":
                cur = node(siblings[j], cur)
            elif directions[j] == "right":
                cur = node(cur, siblings[j])
            else:
                ok_walk = False
                break
        if not ok_walk:
            merkle = False
            continue
        # D4: the proof's own claimed root must equal what it walks to.
        if p.get("merkle_root") != cur:
            merkle = False
        if root is None:
            root = cur
        elif root != cur:
            merkle = False
    # `seen` holds NORMALIZED indices (int) or None for an invalid one. A bijection requires every
    # index valid (no None) and exactly len(receipts) distinct values covering 0..len-1.
    bijection = (
        None not in seen
        and len(seen) == len(receipts)
        and all(isinstance(n, int) and not isinstance(n, bool) and 0 <= n < len(receipts) for n in seen)
    )
    add("merkle_and_bijection", merkle and bijection)

    # §6.5 mandatory signed checkpoint — STRICT schema (D2): exactly the 7 canonical fields +
    # the bound algorithm value, then signature + root/count/head binding.
    cp = bundle.get("checkpoint") if isinstance(bundle, dict) else None
    cp_ok = False
    if has_exact_keys(cp, CHECKPOINT_FIELDS):
        cp_ok = (
            cp.get("algorithm") == ALGO
            and sig_ok(pub, canon(strip(cp, "signature")), cp.get("signature"))
            and root is not None
            and cp.get("merkle_root") == root
            # T4: compare leaf_count NUMERICALLY (2.0 == 2) so a re-encoded count still binds.
            and _count_equals(cp.get("leaf_count"), len(receipts))
            and cp.get("head_leaf_hash") == (leaves[-1] if leaves else "")
        )
    add("signed_checkpoint", cp_ok)

    # §6.5b ENVELOPE CONSISTENCY (D5): per-receipt identity + the UNSIGNED envelope must agree
    # with the signed/recomputed values, so nothing outside the signed objects can mislead a
    # consumer that reads the envelope.
    cp_gateway_id = cp.get("gateway_id") if isinstance(cp, dict) else None
    cp_generated_at = cp.get("generated_at") if isinstance(cp, dict) else None
    bundle_gateway_id = bundle.get("gateway_id") if isinstance(bundle, dict) else None
    bundle_merkle_root = bundle.get("merkle_root") if isinstance(bundle, dict) else None
    bundle_generated_at = bundle.get("generated_at") if isinstance(bundle, dict) else None
    add(
        "envelope_consistency",
        len(receipts) > 0
        and all(isinstance(r, dict) and r.get("public_key") == pub for r in receipts)
        and all(isinstance(r, dict) and r.get("gateway_id") == bundle_gateway_id for r in receipts)
        and cp_gateway_id == bundle_gateway_id
        and root is not None
        and bundle_merkle_root == root
        # T6: bind the UNSIGNED envelope generated_at to the SIGNED checkpoint generated_at (equal
        # by construction) so an unsigned-envelope generated_at lie cannot pass.
        and bundle_generated_at == cp_generated_at,
    )

    # §6.6 provenance (only when a key is pinned)
    issuer_verified = bool(pinned and pub == expected_public_key)
    if pinned:
        add("gateway_key_match", issuer_verified)

    verdict = "VERIFIED" if all(s["ok"] for s in steps) else "FAILED"
    return {
        "verdict": verdict,
        "issuerVerified": issuer_verified,
        "pinned": bool(pinned),
        "steps": steps,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _main(argv):
    import os
    args = argv[1:]
    pubkey = None
    files = []
    i = 0
    while i < len(args):
        if args[i] == "--pubkey":
            pubkey = args[i + 1] if i + 1 < len(args) else None
            i += 2
        elif args[i] == "--ed25519":
            # Opt into the zero-dependency stdlib demonstrator (default is the audited library).
            if i + 1 < len(args) and args[i + 1].strip().lower() == "stdlib":
                os.environ["AGA_VERIFY_ED25519"] = "stdlib"
            i += 2
        else:
            files.append(args[i])
            i += 1
    if not files:
        # Usage error (no bundle argument at all) MAY exit 2; any bundle-verdict path is 0/1.
        sys.stderr.write("usage: python verify_sep.py <bundle.json> [--pubkey <64-hex>] [--ed25519 stdlib]\n")
        return 2
    sys.stderr.write("ed25519 backend: %s\n" % ("stdlib demonstrator" if _stdlib_mode() else "audited library (cryptography/PyNaCl)"))
    # D8: malformed JSON, unreadable bundle content, or ANY exception on the parse/verify path =>
    # print a FAILED line and exit 1 (NOT an uncaught traceback, NOT exit 2).
    try:
        with open(files[0], "r", encoding="utf-8") as fh:
            # parse_constant rejects bare Infinity/-Infinity/NaN (not valid RFC-8259 JSON) so the
            # CLI fails closed at parse, matching JS/Go and avoiding a cross-stack verdict split.
            bundle = json.load(fh, parse_constant=_reject_nonfinite_json)
        # Trichotomy pre-gate (CLI only; verify_sep_bundle is byte-unchanged): this pure-stdlib
        # reference implements ONLY the v1 profile. A bundle declaring a REGISTERED profile it does
        # not implement (the v2 ML-DSA-65+Ed25519 composite) returns UNSUPPORTED_PROFILE (exit 3) with
        # NO soundness claim, never a misleading FAILED. STRICTLY ADDITIVE: runs before the 6-step body
        # and can ONLY convert a would-be FAILED(v2) into exit 3; an unknown/unregistered algorithm
        # still falls through to the structural floor and FAILS.
        if isinstance(bundle, dict) and bundle.get("algorithm") == "ML-DSA-65+Ed25519-SHA256-JCS":
            print("OVERALL: UNSUPPORTED_PROFILE (this v1-only reference does not implement profile %r)" % bundle.get("algorithm"))
            return 3
        r = verify_sep_bundle(bundle, pubkey)
    except Exception as e:  # noqa: BLE001 — fail closed on parse/read/verify error.
        sys.stderr.write("error reading/parsing bundle: %s\n" % (e,))
        print("FAILED")
        return 1
    for s in r["steps"]:
        print("  %s  %s" % ("PASS" if s["ok"] else "FAIL", s["name"]))
    # Suffix reflects the VERDICT: only a VERIFIED bundle gets a provenance/integrity tag; a FAILED
    # bundle prints just "FAILED" (never "FAILED (provenance verified)").
    if r["verdict"] == "VERIFIED":
        tail = " (provenance verified)" if r["pinned"] else " (integrity only; no key pinned)"
    else:
        tail = ""
    print("OVERALL: %s%s" % (r["verdict"], tail))
    print(r["verdict"])
    return 0 if r["verdict"] == "VERIFIED" else 1


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
