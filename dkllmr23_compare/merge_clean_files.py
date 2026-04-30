#!/usr/bin/env python3
import argparse, csv, os

FIELDS = ['scheme','N','B','metric','plot_value','plot_unit','n','m','r','t','q_bits','d','sigma_inf','short_range','message_bits']

def main():
    ap = argparse.ArgumentParser(description='Merge multiple six_plot_data_clean.csv files with identical columns.')
    ap.add_argument('--inputs', nargs='+', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    rows=[]
    for path in args.inputs:
        with open(path, newline='', encoding='utf-8') as f:
            for row in csv.DictReader(f):
                rows.append({k: row.get(k,'') for k in FIELDS})
    with open(args.out, 'w', newline='', encoding='utf-8') as f:
        w=csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader(); w.writerows(rows)
    print(f'Wrote merged file: {args.out}')

if __name__ == '__main__':
    main()
