#!/usr/bin/env python3
"""Convert six_required_data_estimated_time.csv to six_plot_data_clean.csv.

Usage:
  python make_clean_from_estimated.py \
    --input results_estimated_keygen_no_upid/six_required_data_estimated_time.csv \
    --out postrbe_six_plot_data_clean_keygen_no_upid.csv
"""
from __future__ import annotations
import argparse, csv
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()
    inp = Path(args.input)
    outp = Path(args.out)
    rows=[]
    with inp.open('r', newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            metric = r['metric']
            if metric == 'CiphertextSizes':
                plot_value = r.get('value_mib') or ''
                plot_unit = 'MiB'
            else:
                plot_value = r.get('estimated_ms') or r.get('estimated_value') or ''
                plot_unit = 'ms'
            short_range = '{%s,%s}' % (r.get('short_min',''), r.get('short_max',''))
            if r.get('short_min') == '-2' and r.get('short_max') == '2':
                short_range = '{-2,-1,0,1,2}'
            rows.append({
                'scheme': r['scheme'],
                'N': r['N'],
                'B': r['B'],
                'metric': metric,
                'plot_value': plot_value,
                'plot_unit': plot_unit,
                'n': r['n'],
                'm': r['m'],
                'r': r['r'],
                't': r['t'],
                'q_bits': r['q_bits'],
                'd': r['d'],
                'sigma_inf': r['sigma_inf'],
                'short_range': short_range,
                'message_bits': r['message_bits'],
            })
    outp.parent.mkdir(parents=True, exist_ok=True)
    with outp.open('w', newline='', encoding='utf-8') as f:
        fields=['scheme','N','B','metric','plot_value','plot_unit','n','m','r','t','q_bits','d','sigma_inf','short_range','message_bits']
        w=csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(rows)
    print(f'Wrote: {outp}')

if __name__ == '__main__':
    main()
