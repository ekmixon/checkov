import os

from pathlib import Path

home = str(Path.home())
bridgecrew_dir = f"{home}/.bridgecrew"
bridgecrew_file = f"{bridgecrew_dir}/credentials"


def persist_key(key):
    if not os.path.exists(bridgecrew_dir):
        os.makedirs(bridgecrew_dir)
    with open(bridgecrew_file, "w") as f:
        f.write(key)


def read_key():
    key = None
    if os.path.exists(bridgecrew_file):
        with open(bridgecrew_file, "r") as f:
            key = f.readline()
    return key
