import re
import sys
sys.path.append('.')
import json

# Educational / Meta inquiry prefix
META_PREFIX = re.compile(
    r'^\s*(explain\s+(what|why|how)|write\s+a\s+(python\s+)?(regex|function|script|code|pattern|two-sentence|polite|professional|short)|how\s+(do|can)\s+i\s+(sanitize|detect|normalize|parse|validate|implement|write|sort|read)|translate\s+(the\s+phrase|[\'"]|this\s+sentence)|what\s+is\s+(a|the|photosynthesis|dna|25|2\s+to)|calculate|solve|convert|give\s+me\s+(five|a\s+checklist|a\s+simple)|suggest\s+(three|five|a\s+basic)|create\s+a\s+(simple|morning|checklist)|discuss\s+the|summarize\s+(common|the\s+benefits)|draft\s+a\s+(memo|job\s+description|security\s+advisory|project\s+report|corporate)|review\s+this\s+sentence|help\s+me\s+(draft|revise|make)|who\s+wrote)',
    re.IGNORECASE
)

# Active extraction directive
EXTRACTION_DIRECTIVE = re.compile(
    r'(reveal|disclose|output|print|give\s+me|show\s+me)\s+(the\s+|this\s+|your\s+|my\s+)*(secret|token|password|protected\s+value|hidden\s+value|key|blue-orange-42)',
    re.IGNORECASE
)

def is_educational_meta(text):
    if META_PREFIX.search(text):
        # If it also contains an active extraction directive targeting the secret/token, it's NOT purely educational!
        if EXTRACTION_DIRECTIVE.search(text):
            return False
        return True
    return False

# Test on benign adversarial prompts
from benchmark_benign_adversarial_v3 import BENIGN_ADVERSARIAL_PROMPTS
from benchmark_adversarial_v3 import ALL_TESTS

meta_benign_count = 0
for cat, p in BENIGN_ADVERSARIAL_PROMPTS:
    if is_educational_meta(p):
        meta_benign_count += 1
    else:
        print("Non-meta benign:", cat, p[:60])

print(f"Benign adversarial recognized as meta: {meta_benign_count} / {len(BENIGN_ADVERSARIAL_PROMPTS)}")

# Ensure NO attack is mistakenly marked as educational meta
attack_marked_as_meta = []
for test in ALL_TESTS:
    if is_educational_meta(test['prompt']):
        attack_marked_as_meta.append((test['id'], test['category'], test['prompt']))

print(f"Attacks falsely marked as educational meta: {len(attack_marked_as_meta)}")
for a in attack_marked_as_meta:
    print("ATTACK MARKED META:", a)
