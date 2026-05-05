#!/usr/bin/env python3
import csv
import sys

def validate_csv(filename):
    print(f"[*] Validating Schema: {filename}")
    try:
        with open(filename, 'r') as f:
            reader = csv.reader(f)
            header = next(reader)
            cols = len(header)
            print(f"    -> Columns found: {cols}")
            
            if cols != 495:
                print(f"[!] Warning: Expected 495 columns, found {cols}")
            else:
                print("[+] Schema parity confirmed: 495 columns.")
            
            row_count = 0
            for row in reader:
                row_count += 1
                if len(row) != cols:
                    print(f"[!] Error: Row {row_count} has inconsistent column count ({len(row)})")
                    return False
                if row_count >= 10: break
            
            print(f"[+] Data integrity confirmed for first {row_count} rows.")
            return True
    except Exception as e:
        print(f"[!] Validation failed: {e}")
        return False

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "sample_flows.csv"
    if not validate_csv(target):
        sys.exit(1)
