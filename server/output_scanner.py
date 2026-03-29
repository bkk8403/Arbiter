"""
Arbiter — Output Governance Scanner
Scans LLM responses BEFORE they reach the user.

Catches three violation types:
  1. LEAKAGE   — response contains denied data values (salary figures, grades, etc.)
  2. MASK_BREACH — response contains patterns matching masked fields (SSN format)
  3. HALLUCINATION — response contains data-like claims not present in filtered context

Uses the same PolicyDecision that governed the input — same policy, both directions.
Fully generic — no resource names hardcoded. Scans against raw data values.
"""

import re
from typing import Optional


# SSN pattern: 3-2-4 digits
_SSN_PATTERN = re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b")

# Currency pattern: dollar amounts
_CURRENCY_PATTERN = re.compile(r"\$[\d,]+(?:\.\d{2})?")

# Percentage pattern
_PERCENTAGE_PATTERN = re.compile(r"\b\d{1,3}(?:\.\d+)?%")


def scan_output(
    llm_response: str,
    policy,
    raw_data: dict,
    filtered_context: str,
) -> dict:
    """
    Scan an LLM response for governance violations.

    Args:
        llm_response: the raw text the LLM produced
        policy: the PolicyDecision from input governance
        raw_data: the full unfiltered tenant data
        filtered_context: the text that was actually sent to the LLM

    Returns:
        {
            "violations": [{"type": str, "description": str, "severity": str, "redacted_value": str}],
            "sanitized_response": str (with violations redacted),
            "decision": "clean" | "redacted" | "blocked",
        }
    """
    violations = []
    sanitized = llm_response

    # ── Check 1: Mask breaches (SSN patterns in output) ──
    ssn_violations, sanitized = _check_mask_breaches(sanitized, raw_data)
    violations.extend(ssn_violations)

    # ── Check 2: Leakage (denied data values appearing in output) ──
    leak_violations, sanitized = _check_leakage(sanitized, policy, raw_data, filtered_context)
    violations.extend(leak_violations)
    # ── Check 2.5: Inference bypass — withheld values reconstructed ──
    if hasattr(policy, 'inference_withheld_values'):
        for val_info in policy.inference_withheld_values:
            val_str = f"${val_info['value']:,}"
            if val_str in sanitized:
                violations.append({
                    "type": "inference_bypass",
                    "description": (
                        f"LLM reconstructed withheld value {val_str} "
                        f"({val_info['field']}) from component data — "
                        f"inference channel circumvented"
                    ),
                    "severity": "high",
                    "redacted_value": val_str,
                })
                sanitized = sanitized.replace(val_str, "[WITHHELD VALUE REDACTED]")

    # ── Check 3: Hallucination (data claims not in filtered context) ──
    hallucination_violations = _check_hallucination(sanitized, filtered_context, raw_data)
    violations.extend(hallucination_violations)
    # Hallucinations get flagged but not redacted — we can't know which part to remove

    # ── Determine decision ──
    if not violations:
        decision = "clean"
    else:
        severities = [v["severity"] for v in violations]
        if "critical" in severities:
            decision = "blocked"
            sanitized = (
                "[RESPONSE BLOCKED — Output governance detected critical violations. "
                f"{len(violations)} violation(s) caught. "
                "This interaction has been logged for compliance review.]"
            )
        else:
            decision = "redacted"

    return {
        "violations": violations,
        "sanitized_response": sanitized,
        "decision": decision,
    }


# ================================================================
# Check 1: Mask breaches
# ================================================================

def _check_mask_breaches(response: str, raw_data: dict) -> tuple[list[dict], str]:
    """Detect and redact SSN patterns and other masked field values in the response."""
    violations = []
    sanitized = response

    # Collect all real SSNs from the raw data for exact matching
    real_ssns = set()
    for person in raw_data.get("persons", []):
        ssn = person.get("ssn", "")
        if ssn:
            real_ssns.add(ssn)
            # Also add without dashes
            real_ssns.add(ssn.replace("-", ""))

    # Check for SSN patterns
    matches = _SSN_PATTERN.findall(sanitized)
    for match in matches:
        normalized = match.replace(" ", "-").replace(".", "-")
        no_dash = normalized.replace("-", "")

        # Is this a real SSN from our data?
        is_real = normalized in real_ssns or no_dash in real_ssns

        violations.append({
            "type": "mask_breach",
            "description": f"SSN pattern detected in output{' (matches real record)' if is_real else ''}",
            "severity": "critical" if is_real else "high",
            "redacted_value": match[:3] + "...",
        })
        sanitized = sanitized.replace(match, "[SSN REDACTED]")

    return violations, sanitized


# ================================================================
# Check 2: Leakage — denied data values in output
# ================================================================

def _check_leakage(response: str, policy, raw_data: dict, filtered_context: str = "") -> tuple[list[dict], str]:
    """Detect denied data values appearing in the LLM response."""
    violations = []
    sanitized = response

    # Build a set of denied values from raw data for denied resources
    denied_values = _collect_denied_values(policy, raw_data)

    for value_info in denied_values:
        value_str = str(value_info["value"])

        # Skip very short values that would false-positive (e.g., "1", "A")
        if len(value_str) < 4:
            continue

        if value_str in sanitized and value_str not in filtered_context:
            violations.append({
                "type": "leakage",
                "description": (
                    f"Denied {value_info['field']} from {value_info['resource']} "
                    f"detected in output"
                ),
                "severity": "high",
                "redacted_value": value_str[:6] + "...",
            })
            sanitized = sanitized.replace(value_str, f"[{value_info['field'].upper()} REDACTED]")

    # Also check for denied salary/financial figures as formatted currency
    currency_matches = _CURRENCY_PATTERN.findall(sanitized)
    denied_numbers = {v["value"] for v in denied_values if isinstance(v["value"], (int, float))}

    for match in currency_matches:
        # Parse the dollar amount
        try:
            amount = int(match.replace("$", "").replace(",", "").split(".")[0])
        except ValueError:
            continue

        if amount in denied_numbers:
            violations.append({
                "type": "leakage",
                "description": f"Denied financial value ${amount:,} detected in output",
                "severity": "high",
                "redacted_value": match,
            })
            sanitized = sanitized.replace(match, "[FINANCIAL VALUE REDACTED]")

    return violations, sanitized


def _collect_denied_values(policy, raw_data: dict) -> list[dict]:
    """
    Collect specific data values from denied resources.
    These are the values that should NOT appear in the output.
    """
    denied_values = []
    metadata_keys = {"tenant_id", "data_source", "last_updated"}

    for resource_name in policy.denied_resources:
        records = raw_data.get(resource_name, [])
        if not isinstance(records, list):
            continue

        for record in records:
            if not isinstance(record, dict):
                continue
            for field, value in record.items():
                if value is None:
                    continue
                # Track financial values, names, IDs — anything identifiable
                if isinstance(value, (int, float)) and value > 100:
                    denied_values.append({
                        "resource": resource_name,
                        "field": field,
                        "value": value,
                    })
                elif isinstance(value, str) and len(value) >= 4:
                    denied_values.append({
                        "resource": resource_name,
                        "field": field,
                        "value": value,
                    })

    return denied_values


# ================================================================
# Check 3: Hallucination — claims not grounded in filtered context
# ================================================================

def _check_hallucination(response: str, filtered_context: str, raw_data: dict) -> list[dict]:
    """
    Detect when the LLM fabricates data-like claims not present
    in the filtered context it was given.

    Focuses on numeric claims (salaries, GPAs, grades) that look
    like they came from the data but weren't in the authorized context.
    """
    violations = []

    # Collect all numbers from the filtered context (what the LLM was given)
    context_numbers = set()
    for match in re.findall(r"\b\d{2,}\b", filtered_context.replace(",", "")):
        context_numbers.add(match)

    # Collect all numbers from the raw data (what actually exists)
    raw_numbers = {}
    metadata_keys = {"tenant_id", "data_source", "last_updated"}
    for resource_name, records in raw_data.items():
        if resource_name in metadata_keys or not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            for field, value in record.items():
                if isinstance(value, (int, float)) and value > 100:
                    raw_numbers[str(int(value))] = {
                        "resource": resource_name,
                        "field": field,
                        "value": value,
                    }

    # Find numbers in the response that exist in raw data but NOT in filtered context
    response_numbers = re.findall(r"\b\d{3,}\b", response.replace(",", ""))
    for num in response_numbers:
        if num in raw_numbers and num not in context_numbers:
            info = raw_numbers[num]
            violations.append({
                "type": "hallucination",
                "description": (
                    f"Response contains {info['field']}={info['value']} from "
                    f"{info['resource']} which was not in the authorized context — "
                    f"likely hallucinated from training data or inferred"
                ),
                "severity": "medium",
                "redacted_value": num,
            })

    # Check for plausible salary estimates near denied values
    currency_matches = _CURRENCY_PATTERN.findall(response)
    for match in currency_matches:
        try:
            amount = int(match.replace("$", "").replace(",", "").split(".")[0])
        except ValueError:
            continue

        # Check if this amount is close to (within 10%) a denied value
        for raw_num_str, info in raw_numbers.items():
            raw_val = info["value"]
            if isinstance(raw_val, (int, float)) and raw_val > 1000:
                if str(int(raw_val)) not in context_numbers:
                    if abs(amount - raw_val) / raw_val < 0.05 and match not in filtered_context and str(amount) not in context_numbers:
                        violations.append({
                            "type": "hallucination",
                            "description": (
                                f"Response contains ${amount:,} which is within 10% of "
                                f"denied {info['field']}=${int(raw_val):,} — "
                                f"likely inferred from training data"
                            ),
                            "severity": "medium",
                            "redacted_value": match,
                        })
                        break

    return violations