import argparse
from itertools import islice

from pymemcache.client.hash import HashClient

servers = [
    # 1. List memcached host:port here, Example: '127.0.0.1:11211',
]
client = HashClient(servers, timeout=86400 * 30)

# 2. Change as in settings CACHE for alias (Django cache keys are formatted with prefix and version)
key_prefix = ''
version = 1


def turn_hmac_kill_switch(turn_on: bool, key_ids: list):
    cache_keys = [
        f'{key_prefix}:{version}:HMAC_KILL_SWITCH__{id.strip()}' for id in key_ids
    ]
    if turn_on:
        failed = client.set_many(dict((key, True) for key in cache_keys))
        if failed:
            print(f'Unable to turn on switch with cache keys{failed}')
    else:
        client.delete_many(cache_keys)


def process_file(file_abspath: str, turn_on: bool):
    with open(file_abspath, 'r') as f:
        ids = islice(f, 10)
        turn_hmac_kill_switch(turn_on, list(ids))


parser = argparse.ArgumentParser(
    description='Turn hmac kill switch on/off for key ids listed in a file.'
)
parser.add_argument(
    '--abspath',
    type=str,
    required=True,
    help='Absolute path of file with hmac key ids, one per line',
)
parser.add_argument('--switch', type=str, required=True, choices=('on', 'off'))

args = parser.parse_args()

abspath = args.abspath
switch = args.switch
on_off = True if switch == 'on' else False

process_file(abspath, on_off)
