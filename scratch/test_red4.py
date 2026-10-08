import re
import sys
from pathlib import Path
sys.path.insert(0, str(Path(".").resolve()))
from benchmark_benign_adversarial_v3 import BENIGN_ADVERSARIAL_PROMPTS
from benchmark_adversarial_v3 import ATTACK_CATEGORIES
from agentguard import DETERMINISTIC_RULES, ACTIVE_EXTRACTION_PATTERN, input_normalizer

prefix_pattern = re.compile(
    r"^\s*("
    r"explain\s+(what|why|how|the|whether)|"
    r"what\s+(is|are)\s+|"
    r"why\s+is\s+|"
    r"describe\s+|"
    r"discuss\s+|"
    r"summarize\s+|"
    r"how\s+(do|can|does|should)\s+|"
    r"in\s+python,\s+how\s+|"
    r"show\s+me\s+how\s+|"
    r"write\s+a\s+|"
    r"draft\s+(a|an)\s+|"
    r"create\s+a\s+|"
    r"give\s+me\s+|"
    r"suggest\s+|"
    r"translate\s+|"
    r"review\s+|"
    r"help\s+me\s+|"
    r"calculate|solve|convert|who\s+wrote"
    r")",
    re.IGNORECASE,
)

def check_rules(text):
    for pattern, rule_id, attack_type in DETERMINISTIC_RULES:
        if re.search(pattern, text, re.IGNORECASE):
            return rule_id
    return None

def would_pre_check_block(user_input):
    norm_info = input_normalizer(user_input)
    norm = norm_info["normalized"]
    
    # Check if text is educational discussion of attack phrases in quotes
    is_quoted_discussion = bool(re.search(r"(phrases?\s+like|detect|match(es)?|sanitize|parses?)\s+['\"].*?['\"]", norm, re.IGNORECASE))
    
    has_prefix = bool(prefix_pattern.search(norm))
    has_extraction = bool(ACTIVE_EXTRACTION_PATTERN.search(norm))
    
    # Check deterministic rules on normalized text
    rule_match = check_rules(norm)
    
    # Check decoded payloads
    for p in norm_info["decoded_payloads"]:
        if check_rules(p) or ACTIVE_EXTRACTION_PATTERN.search(p):
            return True, "decoded_payload"
            
    if rule_match:
        # If it's a quoted discussion in an educational context without extraction, don't pre-block
        if has_prefix and is_quoted_discussion and not has_extraction:
            return False, "quoted_educational_exception"
        return True, rule_match
        
    return False, None

# Test on 100 attacks
attack_pre_blocked = 0
for cat, prompts in ATTACK_CATEGORIES.items():
    for p in prompts:
        blocked, reason = would_pre_check_block(p)
        if blocked:
            attack_pre_blocked += 1

print(f"Attacks pre-blocked by deterministic rules: {attack_pre_blocked} / 100")

# Test on 50 benign prompts
benign_pre_blocked = 0
for cat, p in BENIGN_ADVERSARIAL_PROMPTS:
    blocked, reason = would_pre_check_block(p)
    if blocked:
        benign_pre_blocked += 1
        print(f"Benign falsely blocked by rule: {reason} | {p}")

print(f"Benign falsely pre-blocked by rules: {benign_pre_blocked} / 50")
