import json
import sys
import os
import glob

# ANSI Colors
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
DIM = '\033[2m'
RESET = '\033[0m'
BOLD = '\033[1m'

def print_logs(filepath, limit=50):
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        return

    print(f"\n{BOLD}=== Reading Normalized Logs from: {filepath} ==={RESET}\n")
    print(f"{BOLD}{'TIMESTAMP':<22} {'SEVERITY':<10} {'TYPE':<15} {'MESSAGE'}{RESET}")
    print("-" * 90)

    count = 0
    threats = 0
    with open(filepath, 'r', encoding='utf-8') as f:
        for line in f:
            if not line.strip(): continue
            try:
                log = json.loads(line)
                ts = log.get('timestamp', '')[:20]
                sev = log.get('severity', 'info').upper()
                ltype = log.get('log_type', 'unknown').upper()
                msg = log.get('message', '')[:100]  # truncate long messages
                
                # Color coding
                if sev == 'CRITICAL' or sev == 'HIGH' or 'THREAT' in log:
                    color = RED + BOLD
                    threats += 1
                elif sev == 'MEDIUM':
                    color = YELLOW
                else:
                    color = RESET

                print(f"{color}{ts:<22} {sev:<10} {ltype:<15} {msg}{RESET}")
                count += 1
                
                if count >= limit:
                    print(f"\n{DIM}... showing first {limit} events ...{RESET}")
                    break
            except Exception as e:
                pass

    print("-" * 90)
    print(f"{BOLD}Total Threats Shown: {threats}{RESET}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_file = sys.argv[1]
    else:
        # Auto-find the newest jsonl file
        files = glob.glob('live_capture_*.jsonl')
        if not files:
            print("No capture files found.")
            sys.exit(1)
        target_file = max(files, key=os.path.getctime)
    
    print_logs(target_file, limit=30)
