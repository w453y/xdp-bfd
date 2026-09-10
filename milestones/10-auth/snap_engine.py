# Engine-side snapshot of the six watched sessions.
import json, sys

WATCH = ['10.66.0.24', '10.66.0.25', '10.66.0.22',
         '10.66.0.10', '10.66.0.18', '10.66.0.11']

d = json.load(open('/tmp/bfd_tx_stats.json'))
out = {'total': len(d['sessions']),
       'up': sum(1 for s in d['sessions'] if s['state'] == 'Up'),
       'stats': d['stats'], 'watched': {}}
for s in d['sessions']:
    if s['peer'] in WATCH and s['family'] == 4:
        out['watched'][s['peer']] = {
            'state': s['state'], 'my_disc': s['my_disc'],
            'remote_disc': s['remote_disc'],
            'up_events': s['up_events'], 'down_events': s['down_events'],
            'rx': s['rx_pkts'], 'tx': s['tx_pkts'],
            'demand': s['demand'], 'last_reason': s['last_reason'],
        }
print(json.dumps(out, indent=1, sort_keys=True))
