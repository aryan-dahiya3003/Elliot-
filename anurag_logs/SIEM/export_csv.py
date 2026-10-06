import json
import csv
import sys
import os
import glob

def convert_to_csv(filepath):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    csv_path = filepath.replace('.jsonl', '.csv')
    
    # We define the columns we want in the CSV
    headers = ['timestamp', 'log_type', 'severity', 'action', 'source_ip', 'destination_ip', 'message']

    print(f"Converting {filepath} -> {csv_path}")
    count = 0

    with open(filepath, 'r', encoding='utf-8') as f_in, \
         open(csv_path, 'w', newline='', encoding='utf-8') as f_out:
        
        writer = csv.DictWriter(f_out, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()

        for line in f_in:
            if not line.strip(): continue
            try:
                log = json.loads(line)
                writer.writerow(log)
                count += 1
            except Exception as e:
                pass

    print(f"Success! Exported {count} logs to {csv_path}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    else:
        files = glob.glob('live_capture_*.jsonl')
        if not files:
            sys.exit(1)
        target_file = max(files, key=os.path.getctime)
    
    convert_to_csv(target_file)
