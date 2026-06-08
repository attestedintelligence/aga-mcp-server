#!/usr/bin/env python3
"""
AGA Evidence Bundle Schema Validator

Validates evidence bundle fixtures against the JSON Schema (Draft 2020-12)
defined in evidence-bundle.schema.json. Also runs negative test cases to
confirm the schema correctly rejects invalid documents.

Usage:
    python validate.py

Exit codes:
    0 - All valid fixtures pass, all negative cases correctly reject.
    1 - One or more validations failed unexpectedly.
"""

import json
import os
import sys
import copy

from jsonschema import Draft202012Validator, ValidationError

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SCHEMA_PATH = os.path.join(SCRIPT_DIR, "evidence-bundle.schema.json")
RECEIPT_SCHEMA_PATH = os.path.join(SCRIPT_DIR, "receipt.schema.json")

# Fixture paths relative to the schema directory
POSITIVE_FIXTURES = [
    ("../examples/bundle.json", "Internal format example bundle"),
    ("../examples/ts-evidence-bundle.json", "SEP format TS example bundle"),
    ("../examples/python-evidence-bundle.json", "SEP format Python example bundle"),
    ("../../aga-k8s/test/fixtures/ts-evidence-bundle.json", "SEP format TS fixture"),
    ("../../aga-k8s/test/fixtures/python-evidence-bundle.json", "SEP format Python fixture"),
    ("../../aga-k8s/test/fixtures/lattice-evidence-bundle.json", "SEP format Lattice fixture"),
]

RECEIPT_FIXTURES = [
    ("../examples/receipt.json", "Standalone receipt example"),
]


def load_json(path):
    """Load a JSON file and return parsed data."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def validate_bundle(validator, data, label, path):
    """Validate a bundle against the schema. Returns True if valid."""
    errors = list(validator.iter_errors(data))
    if errors:
        print(f"  FAIL: {label}")
        print(f"        {path}")
        for err in errors[:5]:
            print(f"        - {err.json_path}: {err.message}")
        return False
    print(f"  PASS: {label}")
    return True


def run_positive_tests(validator):
    """Validate all positive fixture files. Returns (passed, failed) counts."""
    passed = 0
    failed = 0
    skipped = 0

    print("\n=== Positive Tests (valid fixtures) ===\n")

    for rel_path, label in POSITIVE_FIXTURES:
        abs_path = os.path.normpath(os.path.join(SCRIPT_DIR, rel_path))
        if not os.path.exists(abs_path):
            print(f"  SKIP: {label} (file not found: {abs_path})")
            skipped += 1
            continue
        data = load_json(abs_path)
        if validate_bundle(validator, data, label, abs_path):
            passed += 1
        else:
            failed += 1

    if skipped:
        print(f"\n  ({skipped} fixture(s) skipped - files not found)")

    return passed, failed


def run_receipt_tests(receipt_validator):
    """Validate standalone receipt fixtures. Returns (passed, failed) counts."""
    passed = 0
    failed = 0

    print("\n=== Receipt Tests (standalone receipts) ===\n")

    for rel_path, label in RECEIPT_FIXTURES:
        abs_path = os.path.normpath(os.path.join(SCRIPT_DIR, rel_path))
        if not os.path.exists(abs_path):
            print(f"  SKIP: {label} (file not found: {abs_path})")
            continue
        data = load_json(abs_path)
        errors = list(receipt_validator.iter_errors(data))
        if errors:
            print(f"  FAIL: {label}")
            for err in errors[:5]:
                print(f"        - {err.json_path}: {err.message}")
            failed += 1
        else:
            print(f"  PASS: {label}")
            passed += 1

    return passed, failed


def run_negative_tests(validator):
    """
    Run negative test cases to verify the schema rejects invalid documents.
    Returns (passed, failed) counts where passed = correctly rejected.
    """
    print("\n=== Negative Tests (must be rejected) ===\n")

    # Load a valid internal bundle as a base
    base_internal_path = os.path.normpath(
        os.path.join(SCRIPT_DIR, "../examples/bundle.json")
    )
    # Load a valid SEP bundle as a base
    base_sep_path = os.path.normpath(
        os.path.join(SCRIPT_DIR, "../examples/ts-evidence-bundle.json")
    )

    if not os.path.exists(base_internal_path) or not os.path.exists(base_sep_path):
        print("  SKIP: Base fixtures not found, cannot run negative tests.")
        return 0, 0

    base_internal = load_json(base_internal_path)
    base_sep = load_json(base_sep_path)

    negative_cases = []

    # Case 1: Missing schema_version
    c = copy.deepcopy(base_internal)
    del c["schema_version"]
    negative_cases.append((c, "Missing required field: schema_version"))

    # Case 2: Missing bundle_id
    c = copy.deepcopy(base_internal)
    del c["bundle_id"]
    negative_cases.append((c, "Missing required field: bundle_id"))

    # Case 3: Missing generated_at
    c = copy.deepcopy(base_internal)
    del c["generated_at"]
    negative_cases.append((c, "Missing required field: generated_at"))

    # Case 4: Missing public_key
    c = copy.deepcopy(base_internal)
    del c["public_key"]
    negative_cases.append((c, "Missing required field: public_key"))

    # Case 5: Missing receipts
    c = copy.deepcopy(base_internal)
    del c["receipts"]
    negative_cases.append((c, "Missing required field: receipts"))

    # Case 6: Empty receipts array
    c = copy.deepcopy(base_internal)
    c["receipts"] = []
    negative_cases.append((c, "Empty receipts array (minItems: 1)"))

    # Case 7: Missing merkle_proofs
    c = copy.deepcopy(base_internal)
    del c["merkle_proofs"]
    negative_cases.append((c, "Missing required field: merkle_proofs"))

    # Case 8: Invalid public_key pattern (not hex)
    c = copy.deepcopy(base_internal)
    c["public_key"] = "ZZZZ_not_hex_at_all"
    negative_cases.append((c, "Invalid public_key pattern (non-hex)"))

    # Case 9: Invalid schema_version
    c = copy.deepcopy(base_internal)
    c["schema_version"] = "2.0"
    negative_cases.append((c, "Invalid schema_version (not in enum)"))

    # Case 10: Invalid hex in Merkle proof leaf_hash
    c = copy.deepcopy(base_internal)
    c["merkle_proofs"][0]["leaf_hash"] = "not-a-hex-hash"
    negative_cases.append((c, "Invalid Merkle proof leaf_hash (non-hex)"))

    # Case 11: Invalid direction in Merkle proof
    c = copy.deepcopy(base_internal)
    c["merkle_proofs"][0]["directions"][0] = "up"
    negative_cases.append((c, "Invalid Merkle proof direction (not left/right)"))

    # Case 12: Internal format missing artifact (no algorithm field)
    c = copy.deepcopy(base_internal)
    del c["artifact"]
    negative_cases.append((c, "Internal format missing artifact"))

    # Case 13: SEP receipt with invalid decision enum
    c = copy.deepcopy(base_sep)
    c["receipts"][0]["decision"] = "MAYBE"
    negative_cases.append((c, "SEP receipt invalid decision enum"))

    # Case 14: Internal receipt with invalid event_type
    c = copy.deepcopy(base_internal)
    c["receipts"][0]["event_type"] = "INVALID_EVENT"
    negative_cases.append((c, "Internal receipt invalid event_type"))

    # Case 15: Merkle proof with negative leaf_index
    c = copy.deepcopy(base_internal)
    c["merkle_proofs"][0]["leaf_index"] = -1
    negative_cases.append((c, "Merkle proof negative leaf_index"))

    passed = 0
    failed = 0

    for doc, label in negative_cases:
        errors = list(validator.iter_errors(doc))
        if errors:
            print(f"  PASS (rejected): {label}")
            passed += 1
        else:
            print(f"  FAIL (accepted): {label}")
            failed += 1

    return passed, failed


def main():
    print("AGA Evidence Bundle Schema Validator")
    print("=" * 50)

    # Load schemas
    schema = load_json(SCHEMA_PATH)
    receipt_schema = load_json(RECEIPT_SCHEMA_PATH)

    # Validate schemas themselves
    Draft202012Validator.check_schema(schema)
    print("Schema self-check: evidence-bundle.schema.json is valid Draft 2020-12")

    Draft202012Validator.check_schema(receipt_schema)
    print("Schema self-check: receipt.schema.json is valid Draft 2020-12")

    bundle_validator = Draft202012Validator(schema)
    receipt_validator = Draft202012Validator(receipt_schema)

    # Run tests
    pos_pass, pos_fail = run_positive_tests(bundle_validator)
    rcpt_pass, rcpt_fail = run_receipt_tests(receipt_validator)
    neg_pass, neg_fail = run_negative_tests(bundle_validator)

    # Summary
    total_pass = pos_pass + rcpt_pass + neg_pass
    total_fail = pos_fail + rcpt_fail + neg_fail

    print("\n" + "=" * 50)
    print(f"TOTAL: {total_pass} passed, {total_fail} failed")
    print(f"  Positive (bundle):  {pos_pass} passed, {pos_fail} failed")
    print(f"  Positive (receipt): {rcpt_pass} passed, {rcpt_fail} failed")
    print(f"  Negative:           {neg_pass} passed, {neg_fail} failed")

    if total_fail > 0:
        print("\nRESULT: FAIL")
        sys.exit(1)
    else:
        print("\nRESULT: PASS")
        sys.exit(0)


if __name__ == "__main__":
    main()
