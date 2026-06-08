// Command verify-v2 is a SOUND, standalone AGILE Go verifier for the canonical AGA SEP
// Evidence Bundle. It is the SECOND INDEPENDENT-LANGUAGE ORACLE for the v2 profile
// (ML-DSA-65+Ed25519 composite), the counterpart of the in-server noble/JS engine.
//
// It is a faithful port of the v1 reference verify.go (../verify.go) — the §6 six-step
// construction and the H1–H11 hardening are byte-for-byte the SAME, because the SEP
// construction is PROFILE-INVARIANT: only the signature primitive and the public-key
// well-formedness are dispatched per profile.
//
//	v1  Ed25519-SHA256-JCS            -> crypto/ed25519 (stdlib), small-order + non-canonical-y rejected
//	v2  ML-DSA-65+Ed25519-SHA256-JCS  -> CIRCL mldsa65 + crypto/ed25519 composite, AND-verify
//
// The composite primitive mirrors aga-k8s/internal/crypto/backends/hybrid.go (the PROVEN
// Go side, byte-identical to noble/JS by the pinned cross-verify fixtures) AND the JS
// edVerifyHardened guards (component-length checks, all-zero + small-order Ed25519 component
// rejection, trailing-byte reject) so this oracle and the JS engine reach an identical verdict.
//
// Verdict trichotomy: VERIFIED (exit 0) | FAILED (exit 1) | UNSUPPORTED_PROFILE (exit 3).
// This oracle implements BOTH registered profiles, so it never exits 3; a v1-only verifier
// (../verify.go with the registry pre-gate) returns exit 3 on a v2 bundle.
//
// CLI: verify-v2 <bundle.json> [--pubkey <hex>]   prints PASS/FAIL per step + OVERALL; exit 0|1|3.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Profile identifiers + registry (mirror src/sep/profiles.ts).
const (
	algoV1 = "Ed25519-SHA256-JCS"
	algoV2 = "ML-DSA-65+Ed25519-SHA256-JCS"
)

// registeredProfiles is the authoritative registry (algorithm -> profile_version).
var registeredProfiles = map[string]string{algoV1: "1", algoV2: "2"}

// supportedProfiles are the profiles THIS oracle implements (both — it is the agile oracle).
var supportedProfiles = map[string]struct{}{algoV1: {}, algoV2: {}}

func isRegistered(a string) bool { _, ok := registeredProfiles[a]; return ok }
func isSupported(a string) bool  { _, ok := supportedProfiles[a]; return ok }

// MaxCanonDepth bounds canonicalization recursion (anti-DoS) — mirrors canonical.ts MAX_CANON_DEPTH.
const MaxCanonDepth = 100

var sepReceiptFields = []string{
	"receipt_id", "receipt_version", "algorithm", "timestamp", "request_id",
	"method", "tool_name", "decision", "reason", "policy_reference",
	"arguments_hash", "previous_receipt_hash", "gateway_id", "public_key", "signature",
}
var sepCheckpointFields = []string{
	"algorithm", "gateway_id", "generated_at", "head_leaf_hash", "leaf_count", "merkle_root", "signature",
}

// ---------------------------------------------------------------------------
// Canonicalization (mirror of engine `canonicalize`) — depth-bounded.
// ---------------------------------------------------------------------------

func canon(v interface{}) string { return canonRec(v, 0) }

func canonRec(v interface{}, depth int) string {
	if depth > MaxCanonDepth {
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
		return normalizeNumber(t.String())
	case float64:
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
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = encodeJSONString(k) + ":" + canonRec(t[k], depth+1)
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func normalizeNumber(lit string) string {
	if i, err := strconv.ParseInt(lit, 10, 64); err == nil {
		return strconv.FormatInt(i, 10)
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return lit
	}
	if f >= -9007199254740992.0 && f <= 9007199254740992.0 {
		if i := int64(f); float64(i) == f {
			return strconv.FormatInt(i, 10)
		}
	}
	return lit
}

func encodeJSONString(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
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

func leafHash(receipt map[string]interface{}) string { return shaHex([]byte(canon(receipt))) }

func nodeHash(leftHex, rightHex string) string {
	l, e1 := hex.DecodeString(leftHex)
	r, e2 := hex.DecodeString(rightHex)
	if e1 != nil || e2 != nil {
		return ""
	}
	return shaHex(append(append([]byte{}, l...), r...))
}

func strip(m map[string]interface{}, f string) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k != f {
			out[k] = v
		}
	}
	return out
}

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
// v1 key validation: small-order + non-canonical-y rejection (mirror verify.go)
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

var ed25519P = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

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

// sigOkV1 verifies a v1 Ed25519 signature (hex) by pubHex over msg (mirror verify.go sigOk).
func sigOkV1(pubHex, msg, sigHex string) bool {
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
// v2 composite (ML-DSA-65 + Ed25519) — mirror of hybrid.go + JS edVerifyHardened
// ---------------------------------------------------------------------------

const (
	mldsaPubBytes = mldsa65.PublicKeySize // 1952
	mldsaSigBytes = mldsa65.SignatureSize // 3309
	edPubBytes    = ed25519.PublicKeySize // 32
	edSigBytes    = ed25519.SignatureSize // 64
	// composite public key = len32(1952)||mldsa||len32(32)||ed = 1992 bytes -> 3984 lower-hex.
	compositePubHexLen = 1992 * 2
)

// decodeComposite splits len32(a)||a||len32(b)||b; fails closed on short/overrun/trailing bytes
// (mirror hybrid.go DecodeComposite and JS decodeComposite — trailing bytes are a malleability surface).
func decodeComposite(data []byte) ([]byte, []byte, bool) {
	if len(data) < 8 {
		return nil, nil, false
	}
	aLen := binary.BigEndian.Uint32(data[0:4])
	if uint64(4)+uint64(aLen)+4 > uint64(len(data)) {
		return nil, nil, false
	}
	a := data[4 : 4+aLen]
	rest := data[4+aLen:]
	if len(rest) < 4 {
		return nil, nil, false
	}
	bLen := binary.BigEndian.Uint32(rest[0:4])
	if uint64(4)+uint64(bLen) > uint64(len(rest)) {
		return nil, nil, false
	}
	if uint64(4)+uint64(bLen) != uint64(len(rest)) {
		return nil, nil, false // trailing bytes after the second component
	}
	return a, rest[4 : 4+bLen], true
}

// verifyComposite verifies a composite signature over msg under a composite public key (hex).
// Returns true only if BOTH ML-DSA-65 and the (hardened) Ed25519 component verify. Fails closed.
func verifyComposite(pubHex, msg, sigHex string) bool {
	// lower-hex, even length (mirror JS verifyHybrid prefilter; we require lowercase to match the
	// engine + the lowercase-hex discipline elsewhere in the construction).
	if !isLowerHexEven(pubHex) || !isLowerHexEven(sigHex) {
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
	mldsaPub, edPub, ok := decodeComposite(pub)
	if !ok {
		return false
	}
	mldsaSig, edSig, ok := decodeComposite(sig)
	if !ok {
		return false
	}
	if len(mldsaPub) != mldsaPubBytes || len(mldsaSig) != mldsaSigBytes {
		return false
	}
	if len(edPub) != edPubBytes || len(edSig) != edSigBytes {
		return false
	}
	// ML-DSA-65 component (FIPS 204, EMPTY context = nil), mirroring hybrid.go.
	var pk mldsa65.PublicKey
	var pkBuf [mldsa65.PublicKeySize]byte
	copy(pkBuf[:], mldsaPub)
	pk.Unpack(&pkBuf)
	if !mldsa65.Verify(&pk, []byte(msg), nil, mldsaSig) {
		return false
	}
	// Ed25519 component, HARDENED to match JS edVerifyHardened: reject all-zero and small-order keys.
	return edVerifyHardened(edPub, []byte(msg), edSig)
}

// edVerifyHardened mirrors src/sep/hybrid.ts edVerifyHardened: reject all-zero + small-order Ed25519
// public keys, then RFC-8032 verify. Small-order rejection reuses the canonical-encoding set (the same
// guard the JS isSmallOrder() applies); Go's stdlib accepts any 32 bytes, so the set is what enforces it.
func edVerifyHardened(edPub, msg, edSig []byte) bool {
	if len(edPub) != edPubBytes || len(edSig) != edSigBytes {
		return false
	}
	allZero := true
	for _, x := range edPub {
		if x != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}
	if _, bad := smallOrderKeys[hex.EncodeToString(edPub)]; bad {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(edPub), msg, edSig)
}

func isLowerHexEven(s string) bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Profile dispatch (mirror src/sep/profiles.ts)
// ---------------------------------------------------------------------------

func validPubForProfile(algo, pub string) bool {
	switch algo {
	case algoV1:
		return wellFormedKey(pub)
	case algoV2:
		return isHex(pub, compositePubHexLen) && !isAllZeroHex(pub)
	}
	return false
}

func verifyForProfile(algo, pub, msg, sig string) bool {
	switch algo {
	case algoV1:
		return sigOkV1(pub, msg, sig)
	case algoV2:
		return verifyComposite(pub, msg, sig)
	}
	return false
}

func isAllZeroHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] != '0' {
			return false
		}
	}
	return len(s) > 0
}

// ---------------------------------------------------------------------------
// Verification (mirror verify.go VerifySepBundle; only the dispatched bits change)
// ---------------------------------------------------------------------------

type Step struct {
	Name string
	OK   bool
}
type Result struct {
	Verdict        string
	IssuerVerified bool
	Pinned         bool
	Steps          []Step
}

func asString(v interface{}) (string, bool) { s, ok := v.(string); return s, ok }
func asMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}
func asSlice(v interface{}) ([]interface{}, bool) { s, ok := v.([]interface{}); return s, ok }

var canonicalTimestampRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

func isLeap(y int) bool { return y%4 == 0 && (y%100 != 0 || y%400 == 0) }
func daysInMonth(y, m int) int {
	days := [12]int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}
	if m == 2 && isLeap(y) {
		return 29
	}
	return days[m-1]
}
func validTimestamp(v interface{}) bool {
	s, ok := v.(string)
	if !ok || !canonicalTimestampRe.MatchString(s) {
		return false
	}
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
	if hour > 23 || minute > 59 || second > 59 {
		return false
	}
	return true
}

func numToInt(v interface{}) (int, bool) {
	switch t := v.(type) {
	case json.Number:
		i, err := t.Int64()
		if err != nil {
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

// VerifySepBundle is the agile library entry point. expectedPublicKey may be nil or a pinned key
// well-formed for the bundle's profile. NEVER throws — any panic is recovered as FAILED.
func VerifySepBundle(bundle map[string]interface{}, expectedPublicKey *string) (res Result) {
	bundleAlgo, _ := asString(bundle["algorithm"])
	pinnedOK := func() bool {
		return expectedPublicKey != nil && isRegistered(bundleAlgo) && isSupported(bundleAlgo) && validPubForProfile(bundleAlgo, *expectedPublicKey)
	}
	defer func() {
		if r := recover(); r != nil {
			res = Result{Verdict: "FAILED", IssuerVerified: false, Pinned: pinnedOK(), Steps: []Step{{Name: "verifier_exception", OK: false}}}
		}
	}()

	var steps []Step
	add := func(name string, ok bool) bool { steps = append(steps, Step{Name: name, OK: ok}); return ok }

	var receipts []map[string]interface{}
	if raw, ok := asSlice(bundle["receipts"]); ok {
		for _, r := range raw {
			if m, ok := asMap(r); ok {
				receipts = append(receipts, m)
			} else {
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
	bundleGatewayID, _ := asString(bundle["gateway_id"])

	// §6.1 structural floor — supported registered profile + profile-valid key + STRICT receipt schema.
	receiptsExact := len(receipts) > 0
	for _, r := range receipts {
		if !hasExactKeys(r, sepReceiptFields) {
			receiptsExact = false
		}
	}
	structural := isRegistered(bundleAlgo) && isSupported(bundleAlgo) && validPubForProfile(bundleAlgo, pub) &&
		len(receipts) > 0 && len(proofs) == len(receipts) && receiptsExact
	add("structural", structural)

	// §6.2 receipt signatures, under the bundle's profile primitive.
	recSigs := len(receipts) > 0
	for _, r := range receipts {
		if r == nil {
			recSigs = false
			continue
		}
		sig, _ := asString(r["signature"])
		if !verifyForProfile(bundleAlgo, pub, canon(strip(r, "signature")), sig) {
			recSigs = false
		}
	}
	add("receipt_signatures", recSigs)

	leaves := make([]string, len(receipts))
	for i, r := range receipts {
		if r != nil {
			leaves[i] = leafHash(r)
		}
	}

	// §6.3 chain + ordering — canonical fixed-width timestamps, non-decreasing (lexicographic).
	chain := len(receipts) > 0
	prevTs := ""
	havePrev := false
	for i, r := range receipts {
		if r == nil {
			chain = false
			havePrev = false
			continue
		}
		expectPrev := ""
		if i > 0 {
			expectPrev = leaves[i-1]
		}
		prev, _ := asString(r["previous_receipt_hash"])
		if prev != expectPrev {
			chain = false
		}
		if !validTimestamp(r["timestamp"]) {
			chain = false
			havePrev = false
			continue
		}
		tsStr, _ := asString(r["timestamp"])
		if havePrev && tsStr < prevTs {
			chain = false
		}
		prevTs = tsStr
		havePrev = true
	}
	add("chain_and_ordering", chain)

	// §6.4 merkle + bijection.
	root := ""
	rootSet := false
	merkle := len(proofs) == len(receipts) && len(proofs) > 0
	seen := map[int]struct{}{}
	for _, p := range proofs {
		if p == nil {
			merkle = false
			continue
		}
		idx, idxOK := numToInt(p["leaf_index"])
		if !idxOK {
			merkle = false
			continue
		}
		seen[idx] = struct{}{}
		var recomputed string
		if idx >= 0 && idx < len(receipts) && receipts[idx] != nil {
			recomputed = leaves[idx]
		} else {
			recomputed = ""
			merkle = false
		}
		leafHashField, _ := asString(p["leaf_hash"])
		if recomputed == "" || recomputed != leafHashField {
			merkle = false
		}
		cur := leafHashField
		sibs, _ := asSlice(p["siblings"])
		dirs, dirsIsArr := asSlice(p["directions"])
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
	bijection := len(seen) == len(receipts)
	for n := range seen {
		if !(n >= 0 && n < len(receipts)) {
			bijection = false
		}
	}
	add("merkle_and_bijection", merkle && bijection)

	// §6.5 mandatory signed checkpoint — STRICT schema + SAME profile as the bundle, then sig + binding.
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
		cpOK = cpAlgo == bundleAlgo &&
			verifyForProfile(bundleAlgo, pub, canon(strip(cp, "signature")), sig) &&
			rootSet && mr == root &&
			lcOK && lc == len(receipts) &&
			hlh == lastLeaf
	}
	add("signed_checkpoint", cpOK)

	// §6.5b envelope consistency.
	envelopeOK := len(receipts) > 0
	for _, r := range receipts {
		if r == nil {
			envelopeOK = false
			continue
		}
		rPub, _ := asString(r["public_key"])
		if rPub != pub {
			envelopeOK = false
		}
		rGw, _ := asString(r["gateway_id"])
		if rGw != bundleGatewayID {
			envelopeOK = false
		}
	}
	cpGatewayID := ""
	cpGeneratedAt := ""
	if cpIsMap {
		cpGatewayID, _ = asString(cp["gateway_id"])
		cpGeneratedAt, _ = asString(cp["generated_at"])
	} else {
		envelopeOK = false
	}
	if cpGatewayID != bundleGatewayID {
		envelopeOK = false
	}
	bundleGeneratedAt, _ := asString(bundle["generated_at"])
	if bundleGeneratedAt != cpGeneratedAt {
		envelopeOK = false
	}
	bundleMerkleRoot, _ := asString(bundle["merkle_root"])
	if !rootSet || bundleMerkleRoot != root {
		envelopeOK = false
	}
	add("envelope_consistency", envelopeOK)

	// §6.6 provenance (only when a profile-valid key is pinned).
	pinned := pinnedOK()
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
	if file == "" {
		fmt.Fprintln(os.Stderr, "usage: verify-v2 <bundle.json> [--pubkey <hex>]")
		os.Exit(2)
	}
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
	if dec.More() {
		fmt.Println("OVERALL: FAILED (trailing content after bundle JSON)")
		os.Exit(1)
	}

	// Trichotomy pre-gate: a REGISTERED profile this oracle does not implement -> UNSUPPORTED_PROFILE
	// (exit 3), NO soundness claim. The agile oracle implements BOTH profiles, so this never fires here;
	// it is the contract a v1-only verifier honors. An UNKNOWN/unregistered algorithm falls through to
	// the §6.1 structural floor below and FAILS.
	bundleAlgo, _ := asString(bundle["algorithm"])
	if isRegistered(bundleAlgo) && !isSupported(bundleAlgo) {
		fmt.Printf("OVERALL: UNSUPPORTED_PROFILE (this verifier does not implement profile %q)\n", bundleAlgo)
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
