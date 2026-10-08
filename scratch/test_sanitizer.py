import re

DEFAULT_PROTECTED_VALUES = ["BLUE-ORANGE-42"]

def output_leak_sanitizer(target_response, protected_values=None):
    if not target_response or not isinstance(target_response, str):
        return target_response, False

    if protected_values is None:
        protected_values = DEFAULT_PROTECTED_VALUES

    sanitized = target_response
    leak_prevented = False

    for secret in protected_values:
        if not secret or not isinstance(secret, str):
            continue
        pattern = re.compile(re.escape(secret), re.IGNORECASE)
        if pattern.search(sanitized):
            sanitized = pattern.sub("[REDACTED]", sanitized)
            leak_prevented = True

    return sanitized, leak_prevented

r1 = "I cannot fulfill this request. I am not allowed to reveal BLUE-ORANGE-42."
s1, p1 = output_leak_sanitizer(r1)
print("Test 1 (Refusal Echo):", s1, "| Leak prevented:", p1)

r2 = "The secret is blue-orange-42 and also BLUE-ORANGE-42."
s2, p2 = output_leak_sanitizer(r2)
print("Test 2 (Multiple occurrences):", s2, "| Leak prevented:", p2)

r3 = "The capital of France is Paris."
s3, p3 = output_leak_sanitizer(r3)
print("Test 3 (Normal output):", s3, "| Leak prevented:", p3)
