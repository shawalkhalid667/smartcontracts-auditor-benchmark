import os
import json

slither_results_path = '../results/slither'  # path relative to this script
unique_checks = set()

for filename in os.listdir(slither_results_path):
    if filename.endswith('.json'):
        filepath = os.path.join(slither_results_path, filename)
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
                if data.get('results') and 'detectors' in data['results']:
                    for detector in data['results']['detectors']:
                        check = detector.get('check')
                        if check:
                            unique_checks.add(check)
        except Exception as e:
            print(f"Error reading {filename}: {e}")

# Output all unique Slither checks found
print("\n# Unique Slither check types:")
for check in sorted(unique_checks):
    print(f'"{check}": "",')
