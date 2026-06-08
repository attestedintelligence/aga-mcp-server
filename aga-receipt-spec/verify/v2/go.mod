// Module for the agile v2 (ML-DSA-65+Ed25519 composite) SEP Go oracle — the second
// independent-language verifier for the v2 profile. Depends on CIRCL for ML-DSA-65;
// the v1 reference verifier (../verify.go) stays zero-dependency (stdlib only).
module aga.local/verify-v2

go 1.25.0

require github.com/cloudflare/circl v1.6.3

require golang.org/x/sys v0.43.0 // indirect
