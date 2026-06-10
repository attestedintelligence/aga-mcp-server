// Command verify-sep is a SOUND, standalone Go verifier for the canonical AGA
// SEP Evidence Bundle. It is a faithful port of the in-server ENGINE
// (the AGA engine's src/sep/verify.ts + canonical.ts + receipt.ts + checkpoint.ts),
// the GROUND TRUTH for SEP verification, mirroring its semantics exactly so its
// verdicts match the engine: a conformant bundle VERIFIES, every adversarial
// bundle the engine rejects FAILS, and a hostile/malformed bundle yields FAILED
// (never a panic).
//
// Steps (CANONICAL_CONSTRUCTION_v2 §6 over §1-5), mirroring src/sep/verify.ts:
//
//	§6.1 structural floor   algorithm == "Ed25519-SHA256-JCS", well-formed gateway
//	                        public key (incl. small-order + non-canonical-y rejection),
//	                        receipts>0, merkle_proofs.len == receipts.len, AND every
//	                        receipt carries EXACTLY the 15 canonical fields (D1).
//	§6.2 receipt signatures Ed25519 over canon(receipt minus "signature")
//	§6.3 chain + ordering   previous_receipt_hash == prior leaf (first == ""),
//	                        STRICT non-decreasing timestamps: every receipt's
//	                        timestamp must be the CANONICAL .sssZ form (regex +
//	                        pure-integer calendar check, NO date library) and be
//	                        >= the prior's by lexicographic STRING compare (D3/T1).
//	§6.4 merkle + bijection leaf = sha256(canon(full receipt)) (no prefix);
//	                        node = sha256(rawbytes(left)||rawbytes(right));
//	                        walk siblings/directions to a single root; the proof's own
//	                        claimed merkle_root must equal what it walks to (D4);
//	                        index 0..N-1.
//	§6.5 signed checkpoint   EXACTLY the 7 canonical fields (D2) AND
//	                        algorithm == "Ed25519-SHA256-JCS"; Ed25519 over
//	                        canon(checkpoint minus "signature"); merkle_root ==
//	                        recomputed root; leaf_count == receipts.len; head_leaf_hash
//	                        == last leaf.
//	§6.5b envelope consistency  receipts>0; every receipt.public_key == bundle.public_key;
//	                        every receipt.gateway_id == bundle.gateway_id; checkpoint
//	                        gateway_id == bundle.gateway_id; bundle.generated_at ==
//	                        checkpoint.generated_at (T6); recomputed root != null and
//	                        bundle.merkle_root == recomputed root (D5).
//	§6.6 provenance         only when a key is pinned: bundle public_key == pinned.
//
// Robustness: the verification function never throws — any panic (type confusion,
// missing structure, a depth-bomb that trips the depth-bounded canon) is recovered
// and mapped to a FAILED verdict (D6/D7). The CLI maps a malformed-JSON or
// unreadable bundle to a FAILED line and exit 1 (D8); only a missing-file/usage
// error (no bundle argument) exits 2.
//
// Canonicalization is byte-identical to the engine `canonicalize`: objects emit
// {"key":value,...} with keys sorted lexicographically; arrays preserve order;
// scalars use JSON encoding without HTML-escaping; an INTEGRAL number is emitted
// as its shortest integer form (JCS/RFC 8785, T2 — "2", never "2.0"/"2e0"),
// matching JS JSON.stringify for the all-integer SEP numeric fields, while a
// non-integral number keeps its source literal. It is DEPTH-BOUNDED at
// MAX_CANON_DEPTH=100 — input nested
// deeper trips a controlled panic that D6 turns into FAILED (anti-DoS).
//
// Library:  result := VerifySepBundle(bundle, &pinnedHex)
// CLI:      go run verify.go <bundle.json> [--pubkey <64-hex>]
//           prints PASS/FAIL per step, "OVERALL: VERIFIED|FAILED", exits 0|1.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const algo = "Ed25519-SHA256-JCS"

// MaxCanonDepth bounds canonicalization recursion (anti-DoS). Mirrors the engine
// canonical.ts MAX_CANON_DEPTH: input nested deeper than this trips a controlled
// panic (recovered by VerifySepBundle => FAILED) instead of a stack overflow.
const MaxCanonDepth = 100

// sepReceiptFields is the EXACT canonical field set of a signed SEP receipt
// (mirrors src/sep/receipt.ts SEP_RECEIPT_FIELDS). The structural floor requires
// a receipt to carry exactly these 15 keys — no more, no less, no rename, no
// "__proto__" injection.
var sepReceiptFields = []string{
	"receipt_id", "receipt_version", "algorithm", "timestamp", "request_id",
	"method", "tool_name", "decision", "reason", "policy_reference",
	"arguments_hash", "previous_receipt_hash", "gateway_id", "public_key", "signature",
}

// sepCheckpointFields is the EXACT canonical field set of a signed SEP checkpoint
// (mirrors src/sep/checkpoint.ts SEP_CHECKPOINT_FIELDS): exactly these 7 keys.
var sepCheckpointFields = []string{
	"algorithm", "gateway_id", "generated_at", "head_leaf_hash", "leaf_count", "merkle_root", "signature",
}

// ---------------------------------------------------------------------------
// Canonicalization (mirror of engine `canonicalize`) — depth-bounded.
// ---------------------------------------------------------------------------

// canon serializes a decoded JSON value to the canonical byte string. The input
// must be the result of json.Unmarshal with UseNumber() so that:
//   - objects are map[string]interface{}
//   - arrays are []interface{}
//   - numbers are json.Number (preserving the exact source literal)
//   - strings are string, booleans bool, null nil
//
// It is depth-bounded: nesting beyond MaxCanonDepth panics with a controlled
// error (recovered by VerifySepBundle => FAILED), matching the engine canonical.ts
// which throws at depth > MAX_CANON_DEPTH and lets the try/catch fail closed.
func canon(v interface{}) string {
	return canonRec(v, 0)
}

func canonRec(v interface{}, depth int) string {
	if depth > MaxCanonDepth {
		// Controlled failure: D7 anti-DoS. Recovered by VerifySepBundle => FAILED.
		panic(fmt.Sprintf("canon: input nesting exceeds %d levels", MaxCanonDepth))
	}
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case json.Number:
		// JCS / RFC 8785 (T2): an INTEGRAL number canonicalizes to its shortest
		// integer form ("2", never "2.0" / "2e0" / "2.0e0"), matching JS
		// JSON.stringify of an integer byte-for-byte. SEP signed numeric fields
		// (checkpoint.leaf_count, proof leaf_index/leaf_count) are integers, so a
		// value re-encoded as 2.0 / 2e0 canonicalizes IDENTICALLY to 2 and its
		// signature still verifies on all six stacks. Non-integral values keep
		// their source literal.
		return normalizeNumber(t.String())
	case float64:
		// UseNumber() means floats normally don't appear, but if one does, apply
		// the same integral-normalization so a stray float64 matches JS output.
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case string:
		return encodeJSONString(t)
	case []interface{}:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = canonRec(e, depth+1)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // lexicographic, matching Object.keys().sort()
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = encodeJSONString(k) + ":" + canonRec(t[k], depth+1)
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		// Any other type should never appear (json.Number/float64 are handled
		// above); fall back to a marshalled form to avoid a silent panic.
		b, _ := json.Marshal(t)
		return string(b)
	}
}

// normalizeNumber implements the T2 (JCS / RFC 8785) integral-number rule for a
// json.Number's source literal: if the value is integral, return its shortest
// integer form ("2", never "2.0" / "2e0" / "2.0e0" / "2E0"), matching JS
// JSON.stringify of an integer byte-for-byte. A non-integral value (e.g. "0.5")
// is returned unchanged, preserving the engine's source-literal behavior for the
// numbers the SEP profile never signs.
func normalizeNumber(lit string) string {
	// Int64 fast path: literals with no '.', 'e', or 'E' parse directly.
	if i, err := strconv.ParseInt(lit, 10, 64); err == nil {
		return strconv.FormatInt(i, 10)
	}
	// Float path: JCS / RFC 8785 serializes numbers as IEEE-754 doubles — exactly what JS
	// JSON.parse and Python json.loads produce — so round via float64, NOT big.Float, or a
	// sub-ULP literal like "2.0000000000000001" would canonicalize differently here than on the
	// JS/Python stacks (a cross-stack divergence). Emit the integer form only within the exact
	// integer range (covers every real leaf_count); degenerate large/exponential values are left
	// as-is and fail the count/signature check uniformly on every stack.
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return lit // unparseable as a float: leave the source literal untouched
	}
	if f >= -9007199254740992.0 && f <= 9007199254740992.0 {
		if i := int64(f); float64(i) == f {
			return strconv.FormatInt(i, 10)
		}
	}
	return lit // non-integral or out of exact-integer range: keep the source literal
}

// encodeJSONString emits a JSON string literal WITHOUT HTML escaping, matching
// JS JSON.stringify for the ASCII SEP fields and preserving raw UTF-8 for
// unicode (the engine relies on JS JSON.stringify, which does not escape
// <, >, & and emits non-ASCII verbatim).
func encodeJSONString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Encode appends a trailing newline; trim it.
	_ = enc.Encode(s)
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	// Go's encoding/json ALWAYS escapes U+2028/U+2029 (LINE/PARAGRAPH SEPARATOR) even with
	// SetEscapeHTML(false) (no flag disables it); JS JSON.stringify and Python json.dumps emit them
	// verbatim per RFC 8785/JCS. Un-escape the 6-byte ASCII escape sequence (0x5c is the ASCII
	// backslash, then u 2 0 2 8/9) back to the raw 3-byte UTF-8 char so the canon is byte-identical
	// across stacks. A literal backslash in data is emitted doubled, so only genuine separators match.
	out = bytes.ReplaceAll(out, []byte{0x5c, 'u', '2', '0', '2', '8'}, []byte{0xe2, 0x80, 0xa8})
	out = bytes.ReplaceAll(out, []byte{0x5c, 'u', '2', '0', '2', '9'}, []byte{0xe2, 0x80, 0xa9})
	return string(out)
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// leafHash = sha256(utf8(canon(full receipt))), no domain prefix (§3).
func leafHash(receipt map[string]interface{}) string {
	return shaHex([]byte(canon(receipt)))
}

// nodeHash = sha256(rawbytes(left) || rawbytes(right)) where left/right are
// 32-byte hex digests (§5). Returns "" if either side is not valid hex.
func nodeHash(leftHex, rightHex string) string {
	l, e1 := hex.DecodeString(leftHex)
	r, e2 := hex.DecodeString(rightHex)
	if e1 != nil || e2 != nil {
		return ""
	}
	return shaHex(append(append([]byte{}, l...), r...))
}

// strip returns a shallow copy of m without field f (mirrors engine `strip`).
func strip(m map[string]interface{}, f string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k != f {
			out[k] = v
		}
	}
	return out
}

// hasExactKeys reports whether m carries EXACTLY the given canonical fields — no
// extra, missing, renamed, duplicate, or "__proto__"-injected key. Mirrors the
// engine hasExactKeys: own-key-count == len(fields) AND each field present as an
// own property. A nil/non-object value fails. (A JSON-parsed "__proto__" is an
// ordinary Go map key, so a 16th key fails the count; a duplicate JSON key is
// collapsed by the decoder, dropping the count below the required size, which
// also fails — both reject, matching the engine's intent.)
func hasExactKeys(m map[string]interface{}, fields []string) bool {
	if m == nil {
		return false
	}
	if len(m) != len(fields) {
		return false
	}
	for _, f := range fields {
		if _, ok := m[f]; !ok {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Key validation: small-order + non-canonical-y rejection
// ---------------------------------------------------------------------------

var smallOrderKeys = map[string]struct{}{}

func init() {
	add := func(h string) { smallOrderKeys[h] = struct{}{} }
	add(strings.Repeat("00", 32))
	add(strings.Repeat("00", 31) + "80")
	add("01" + strings.Repeat("00", 31))
	add("01" + strings.Repeat("00", 30) + "80")
	add("ec" + strings.Repeat("ff", 30) + "7f")
	add("ec" + strings.Repeat("ff", 31))
	add("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")
	add("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")
	add("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85")
	add("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa")
}

// ed25519P = 2^255 - 19
var ed25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

// isHex reports whether s is exactly n lowercase hex chars.
func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isCanonicalY decodes the little-endian y (top sign bit cleared) and reports
// whether y < p. Non-canonical encodings (y >= p) are rejected.
func isCanonicalY(h string) bool {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		return false
	}
	y := new(big.Int)
	for i := 31; i >= 0; i-- {
		v := b[i]
		if i == 31 {
			v &= 0x7f
		}
		y.Lsh(y, 8)
		y.Or(y, big.NewInt(int64(v)))
	}
	return y.Cmp(ed25519P) < 0
}

// wellFormedKey mirrors the engine: 64 lowercase hex, not a small-order
// encoding, canonical y, and a decodable Ed25519 point. ed25519 in Go's stdlib
// accepts any 32 bytes as a public key; the small-order + canonical-y screens
// are what enforce soundness here, matching the engine's createPublicKey guard
// which rejects the same set.
func wellFormedKey(h string) bool {
	if !isHex(h, 64) {
		return false
	}
	if _, bad := smallOrderKeys[h]; bad {
		return false
	}
	if !isCanonicalY(h) {
		return false
	}
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return false
	}
	return true
}

// sigOk verifies an Ed25519 signature (hex) by pubHex over the UTF-8 message.
// Rejects malformed keys, non-128-hex signatures, and all-zero signatures
// (mirrors the engine verifyHex guards).
func sigOk(pubHex, msg, sigHex string) bool {
	if !wellFormedKey(pubHex) || !isHex(sigHex, 128) {
		return false
	}
	allZero := true
	for i := 0; i < len(sigHex); i++ {
		if sigHex[i] != '0' {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), []byte(msg), sig)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// Step is one named check result.
type Step struct {
	Name string
	OK   bool
}

// Result is the verdict plus per-step detail.
type Result struct {
	Verdict        string // "VERIFIED" | "FAILED"
	IssuerVerified bool
	Pinned         bool
	Steps          []Step
}

func asString(v interface{}) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func asMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

func asSlice(v interface{}) ([]interface{}, bool) {
	s, ok := v.([]interface{})
	return s, ok
}

// canonicalTimestampRe is the EXACT canonical SEP timestamp grammar (T1a): a
// 4-digit year, 2-digit month/day, 'T', 2-digit hour/minute/second, a literal
// '.', EXACTLY 3 fractional digits, and a literal uppercase 'Z' — precisely what
// Date.prototype.toISOString() emits. The character class is the LITERAL [0-9]
// (NOT \d): Go's \d, like Python's, matches Unicode digits, which would diverge
// across stacks. Anchored ^...$ so no leading/trailing slop is accepted.
var canonicalTimestampRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

// isLeap reports whether y is a Gregorian leap year, by PURE INTEGER ARITHMETIC
// (T1b): divisible by 4, except centuries unless divisible by 400.
func isLeap(y int) bool {
	return y%4 == 0 && (y%100 != 0 || y%400 == 0)
}

// daysInMonth returns the number of days in month m (1..12) of year y, by PURE
// INTEGER ARITHMETIC (T1b) — NO date library.
func daysInMonth(y, m int) int {
	days := [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if m == 2 && isLeap(y) {
		return 29
	}
	return days[m-1]
}

// validTimestamp implements the canonical SEP timestamp validation (T1): a value
// is VALID iff it is a string matching canonicalTimestampRe (T1a) AND its
// calendar fields are in range, computed with PURE INTEGER ARITHMETIC and NO date
// library (T1b). Because the regex fixes the field widths, slicing is safe and
// strconv.Atoi cannot fail on the captured digit runs. Replaces all native date
// parsing (no time.Parse / Date.parse / fromisoformat); ordering is done by the
// caller as a lexicographic STRING compare on the fixed-width zero-padded form.
func validTimestamp(v interface{}) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	if !canonicalTimestampRe.MatchString(s) {
		return false
	}
	// Fixed positions guaranteed by the anchored regex:
	//   0123456789...  YYYY-MM-DDTHH:MM:SS.mmmZ
	year, _ := strconv.Atoi(s[0:4])
	month, _ := strconv.Atoi(s[5:7])
	day, _ := strconv.Atoi(s[8:10])
	hour, _ := strconv.Atoi(s[11:13])
	minute, _ := strconv.Atoi(s[14:16])
	second, _ := strconv.Atoi(s[17:19])
	if month < 1 || month > 12 {
		return false
	}
	if day < 1 || day > daysInMonth(year, month) {
		return false
	}
	if hour > 23 {
		return false
	}
	if minute > 59 {
		return false
	}
	if second > 59 {
		return false
	}
	return true
}

// VerifySepBundle is the library entry point. expectedPublicKey may be nil
// (integrity-only) or a pointer to a pinned 64-hex gateway key (provenance).
//
// It NEVER throws (D6): any panic — type confusion, missing structure, or the
// depth-bounded canon tripping on a depth-bomb (D7) — is recovered and mapped to
// a FAILED verdict, never propagated to the caller.
func VerifySepBundle(bundle map[string]interface{}, expectedPublicKey *string) (res Result) {
	// D6/D7: catch ALL panics and return FAILED instead of crashing.
	defer func() {
		if r := recover(); r != nil {
			res = Result{
				Verdict:        "FAILED",
				IssuerVerified: false,
				Pinned:         expectedPublicKey != nil && isHex(*expectedPublicKey, 64),
				Steps:          []Step{{Name: "verifier_exception", OK: false}},
			}
		}
	}()

	var steps []Step
	add := func(name string, ok bool) bool {
		steps = append(steps, Step{Name: name, OK: ok})
		return ok
	}

	// Extract receipts / proofs / public key with engine-faithful coercion.
	var receipts []map[string]interface{}
	if raw, ok := asSlice(bundle["receipts"]); ok {
		for _, r := range raw {
			if m, ok := asMap(r); ok {
				receipts = append(receipts, m)
			} else {
				// Non-object entry: keep a nil placeholder so length matches and
				// downstream checks fail cleanly.
				receipts = append(receipts, nil)
			}
		}
	}
	var proofs []map[string]interface{}
	if raw, ok := asSlice(bundle["merkle_proofs"]); ok {
		for _, p := range raw {
			if m, ok := asMap(p); ok {
				proofs = append(proofs, m)
			} else {
				proofs = append(proofs, nil)
			}
		}
	}
	pub, _ := asString(bundle["public_key"])
	bundleAlgo, _ := asString(bundle["algorithm"])
	bundleGatewayID, _ := asString(bundle["gateway_id"])

	// §6.1 structural floor — incl. STRICT receipt schema (D1): every receipt must
	// carry EXACTLY the 15 canonical fields (rejects extra/missing/renamed/duplicate
	// or "__proto__"-injected keys on every signed receipt).
	receiptsExact := len(receipts) > 0
	for _, r := range receipts {
		if !hasExactKeys(r, sepReceiptFields) {
			receiptsExact = false
		}
	}
	structural := bundleAlgo == algo && wellFormedKey(pub) &&
		len(receipts) > 0 && len(proofs) == len(receipts) && receiptsExact
	add("structural", structural)

	// §6.2 receipt signatures
	recSigs := len(receipts) > 0
	for _, r := range receipts {
		if r == nil {
			recSigs = false
			continue
		}
		sig, _ := asString(r["signature"])
		if !sigOk(pub, canon(strip(r, "signature")), sig) {
			recSigs = false
		}
	}
	add("receipt_signatures", recSigs)

	// Precompute leaves once (used by chain, merkle, checkpoint).
	leaves := make([]string, len(receipts))
	for i, r := range receipts {
		if r != nil {
			leaves[i] = leafHash(r)
		}
	}

	// §6.3 chain linkage + STRICT non-decreasing timestamps (D3, T1). For EVERY
	// receipt the timestamp must be VALID under the canonical SEP grammar +
	// integer calendar check (validTimestamp); an invalid one => FAIL. ORDERING:
	// because the canonical form is fixed-width zero-padded UTC, timestamps are
	// compared as PLAIN STRINGS (lexicographic) — for i>0, ts[i] >= ts[i-1] as a
	// string compare (EQUAL allowed). The first receipt only needs to be VALID; no
	// epoch/Date conversion is used for ordering. prevTs holds the prior receipt's
	// timestamp string (havePrev guards the first iteration / a prior nil receipt).
	chain := len(receipts) > 0
	prevTs := ""
	havePrev := false
	for i, r := range receipts {
		if r == nil {
			chain = false
			havePrev = false // a nil receipt breaks the comparison anchor
			continue
		}
		expectPrev := ""
		if i > 0 {
			expectPrev = leaves[i-1]
		}
		prev, _ := asString(r["previous_receipt_hash"]) // missing -> "" (|| '' in engine)
		if prev != expectPrev {
			chain = false
		}
		if !validTimestamp(r["timestamp"]) {
			chain = false    // invalid grammar / out-of-range calendar => fail
			havePrev = false // no usable anchor for the next receipt's ordering
			continue
		}
		tsStr, _ := asString(r["timestamp"]) // validTimestamp guarantees string
		if havePrev && tsStr < prevTs {      // lexicographic; EQUAL allowed
			chain = false
		}
		prevTs = tsStr
		havePrev = true
	}
	add("chain_and_ordering", chain)

	// §6.4 merkle: recompute leaf, walk proof to a single root, per-proof claimed
	// root must match what it walks to (D4), index bijection.
	root := ""
	rootSet := false
	merkle := len(proofs) == len(receipts) && len(proofs) > 0
	seen := map[int]struct{}{}
	for _, p := range proofs {
		if p == nil {
			merkle = false
			continue
		}
		// leaf_index
		idx, idxOK := numToInt(p["leaf_index"])
		if !idxOK {
			merkle = false
			continue
		}
		seen[idx] = struct{}{}
		// recomputed leaf must exist and match the proof's leaf_hash
		var recomputed string
		if idx >= 0 && idx < len(receipts) && receipts[idx] != nil {
			recomputed = leaves[idx]
		} else {
			recomputed = "" // null in engine
			merkle = false
		}
		leafHashField, _ := asString(p["leaf_hash"])
		if recomputed == "" || recomputed != leafHashField {
			merkle = false
		}
		// walk siblings/directions
		cur := leafHashField
		sibs, _ := asSlice(p["siblings"])
		dirs, dirsIsArr := asSlice(p["directions"])
		// C1 MERKLE DIRECTIONS STRICTNESS: directions is UNSIGNED, so a rewritten
		// token like "right"->"RIGHT" must not silently walk to the correct root via
		// an else/ternary fallthrough. REQUIRE directions to be a well-formed array:
		// it is an array, len(directions)==len(siblings), and EVERY element is exactly
		// the literal string "left" or "right" (reject "RIGHT", "", 0, null, missing,
		// or any other token). Otherwise the merkle step FAILS. Mirrors Python and the
		// JS guard so all six stacks agree.
		dirsWellFormed := dirsIsArr && len(dirs) == len(sibs)
		if dirsWellFormed {
			for _, d := range dirs {
				ds, ok := asString(d)
				if !ok || (ds != "left" && ds != "right") {
					dirsWellFormed = false
					break
				}
			}
		}
		// SIBLING HEX STRICTNESS: siblings flow through hex.DecodeString (case-insensitive), so an
		// uppercased sibling decodes to identical bytes and VERIFIES on Go/JS while Python's lowercase
		// is_hex guard FAILs it -- a cross-stack split. Require lowercase 64-hex siblings everywhere.
		sibsWellFormed := true
		for _, s := range sibs {
			ss, ok := asString(s)
			if !ok || !isHex(ss, 64) {
				sibsWellFormed = false
				break
			}
		}
		if !dirsWellFormed || !sibsWellFormed {
			merkle = false
		}
		for j := 0; j < len(sibs); j++ {
			sib, _ := asString(sibs[j])
			dir := ""
			if j < len(dirs) {
				dir, _ = asString(dirs[j])
			}
			if dir == "left" {
				cur = nodeHash(sib, cur)
			} else {
				cur = nodeHash(cur, sib)
			}
		}
		// D4: the proof's own claimed merkle_root must equal what it walks to.
		claimedRoot, _ := asString(p["merkle_root"])
		if claimedRoot != cur {
			merkle = false
		}
		if !rootSet {
			root = cur
			rootSet = true
		} else if root != cur {
			merkle = false
		}
	}
	// bijection: seen covers exactly 0..N-1
	bijection := len(seen) == len(receipts)
	for n := range seen {
		if !(n >= 0 && n < len(receipts)) {
			bijection = false
		}
	}
	add("merkle_and_bijection", merkle && bijection)

	// §6.5 mandatory signed checkpoint — STRICT schema (D2): EXACTLY the 7 canonical
	// fields AND algorithm == "Ed25519-SHA256-JCS", then signature + root/count/head
	// binding.
	cp, cpIsMap := asMap(bundle["checkpoint"])
	cpOK := false
	if cpIsMap && hasExactKeys(cp, sepCheckpointFields) {
		cpAlgo, _ := asString(cp["algorithm"])
		sig, _ := asString(cp["signature"])
		mr, _ := asString(cp["merkle_root"])
		hlh, _ := asString(cp["head_leaf_hash"])
		lc, lcOK := numToInt(cp["leaf_count"])
		lastLeaf := ""
		if len(leaves) > 0 {
			lastLeaf = leaves[len(leaves)-1]
		}
		cpOK = cpAlgo == algo &&
			sigOk(pub, canon(strip(cp, "signature")), sig) &&
			rootSet && mr == root &&
			lcOK && lc == len(receipts) &&
			hlh == lastLeaf
	}
	add("signed_checkpoint", cpOK)

	// §6.5b envelope consistency (D5): per-receipt identity + the UNSIGNED envelope
	// must agree with the signed/recomputed values, so nothing outside the signed
	// objects can mislead a consumer that reads the envelope.
	envelopeOK := len(receipts) > 0
	for _, r := range receipts {
		if r == nil {
			envelopeOK = false
			continue
		}
		rPub, _ := asString(r["public_key"])
		if rPub != pub { // every receipt signed under the bundle key
			envelopeOK = false
		}
		rGw, _ := asString(r["gateway_id"])
		if rGw != bundleGatewayID { // receipts <-> envelope gateway_id
			envelopeOK = false
		}
	}
	cpGatewayID := ""
	cpGeneratedAt := ""
	if cpIsMap {
		cpGatewayID, _ = asString(cp["gateway_id"])
		cpGeneratedAt, _ = asString(cp["generated_at"])
	} else {
		envelopeOK = false // no checkpoint object => cannot agree with envelope
	}
	if cpGatewayID != bundleGatewayID { // checkpoint <-> envelope gateway_id
		envelopeOK = false
	}
	// T6: bind the UNSIGNED bundle.generated_at to the SIGNED checkpoint.generated_at
	// (equal by construction). This closes an unsigned-envelope generated_at lie.
	// bundle_id / schema_version / policy_reference / offline_capable are NOT bound
	// (no signed counterpart; documented residual).
	bundleGeneratedAt, _ := asString(bundle["generated_at"])
	if bundleGeneratedAt != cpGeneratedAt {
		envelopeOK = false
	}
	bundleMerkleRoot, _ := asString(bundle["merkle_root"])
	if !rootSet || bundleMerkleRoot != root { // envelope merkle_root <-> recomputed
		envelopeOK = false
	}
	add("envelope_consistency", envelopeOK)

	// §6.6 provenance (only when pinned)
	pinned := expectedPublicKey != nil && isHex(*expectedPublicKey, 64)
	issuerVerified := pinned && pub == *expectedPublicKey
	if pinned {
		add("gateway_key_match", issuerVerified)
	}

	verdict := "VERIFIED"
	for _, s := range steps {
		if !s.OK {
			verdict = "FAILED"
			break
		}
	}
	return Result{Verdict: verdict, IssuerVerified: issuerVerified, Pinned: pinned, Steps: steps}
}

// numToInt converts a json.Number (or rare float64) to an int, requiring an
// integral value. Mirrors the engine's strict === against an integer count.
func numToInt(v interface{}) (int, bool) {
	switch t := v.(type) {
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			// Could be a float literal like "3.0"; reject (engine uses === on int).
			f, ferr := t.Float64()
			if ferr != nil || f != float64(int64(f)) {
				return 0, false
			}
			return int(int64(f)), true
		}
		return int(i), true
	case float64:
		if t != float64(int64(t)) {
			return 0, false
		}
		return int(int64(t)), true
	default:
		return 0, false
	}
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

func main() {
	args := os.Args[1:]
	var file string
	var pubkey *string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--pubkey" {
			if i+1 < len(args) {
				v := args[i+1]
				pubkey = &v
				i++
			}
			continue
		}
		if !strings.HasPrefix(a, "--") && file == "" {
			file = a
		}
	}
	// Missing-file / usage error (no bundle argument): MAY exit 2 (D8).
	if file == "" {
		fmt.Fprintln(os.Stderr, "usage: go run verify.go <bundle.json> [--pubkey <64-hex>]")
		os.Exit(2)
	}
	// D8: an unreadable bundle or malformed JSON on the bundle is a FAILED verdict
	// (exit 1), NOT an uncaught error / exit 2. Only the missing-arg usage case above
	// exits 2.
	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("OVERALL: FAILED (could not read bundle: %v)\n", err)
		os.Exit(1)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var bundle map[string]interface{}
	if err := dec.Decode(&bundle); err != nil {
		fmt.Printf("OVERALL: FAILED (malformed bundle JSON: %v)\n", err)
		os.Exit(1)
	}
	// Whole-document parse: reject any trailing content after the bundle value (a second JSON
	// document, junk, etc.). JS JSON.parse and Python json.load are whole-document parsers and
	// reject this; a streaming Decode alone silently ignores it — a cross-stack divergence where a
	// Go relying party would accept a file every other verifier rejects. (Trailing whitespace is
	// fine: More() skips it and reports false at EOF.)
	if dec.More() {
		fmt.Println("OVERALL: FAILED (trailing content after bundle JSON)")
		os.Exit(1)
	}
	// Trichotomy pre-gate (CLI only; the library VerifySepBundle is byte-unchanged): this
	// zero-dependency reference implements ONLY the v1 profile. A bundle declaring a REGISTERED
	// profile this verifier does not implement (the v2 ML-DSA-65+Ed25519 composite) returns
	// UNSUPPORTED_PROFILE (exit 3) with NO soundness claim — never a misleading FAILED. STRICTLY
	// ADDITIVE: it runs BEFORE §6 and can ONLY convert a would-be FAILED(v2) into exit 3; an unknown/
	// unregistered algorithm still falls through to the §6.1 structural floor and FAILS. The §1–6
	// construction, canon, and v1 verification are byte-unchanged.
	if ba, _ := bundle["algorithm"].(string); ba == "ML-DSA-65+Ed25519-SHA256-JCS" {
		fmt.Printf("OVERALL: UNSUPPORTED_PROFILE (this v1-only reference does not implement profile %q)\n", ba)
		os.Exit(3)
	}
	res := VerifySepBundle(bundle, pubkey)
	for _, s := range res.Steps {
		status := "FAIL"
		if s.OK {
			status = "PASS"
		}
		fmt.Printf("  %s  %s\n", status, s.Name)
	}
	// T5: the OVERALL suffix must reflect the VERDICT. Print a provenance/integrity
	// suffix ONLY when the verdict is VERIFIED; on FAILED print just FAILED (so a
	// failed+pinned bundle never prints "(provenance verified)"). Exit code is
	// unchanged.
	suffix := ""
	if res.Verdict == "VERIFIED" {
		suffix = " (integrity only; no key pinned)"
		if res.Pinned {
			if res.IssuerVerified {
				suffix = " (provenance verified)"
			} else {
				suffix = " (provenance FAILED)"
			}
		}
	}
	fmt.Printf("OVERALL: %s%s\n", res.Verdict, suffix)
	if res.Verdict == "VERIFIED" {
		os.Exit(0)
	}
	os.Exit(1)
}
