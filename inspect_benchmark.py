import json

with open("benchmark_v10_results.json", "r", encoding="utf-8") as f:
    d = json.load(f)

for c in d['test_cases']:
    if not c['passed']:
        print(f"[{c['category']}] {c['name']}")
        print(f"  details: {c.get('details')}")
        print(f"  expected: {c.get('expected')}")
        print(f"  actual: {c.get('actual')}")
        print()
