"""Secrets come from the platform at run time. No secret is written in code.

Order of lookup: a file mounted by the secret manager (the path is given by
NAME_FILE), then the environment variable NAME. Both are injected by the
deployment (see deploy/k8s.yaml and compose.yaml).
"""

import os


class SecretUnavailable(RuntimeError):
    pass


def get_secret(name):
    file_path = os.environ.get(name + "_FILE")
    if file_path and os.path.isfile(file_path):
        with open(file_path, "r", encoding="utf-8") as handle:
            return handle.read().strip().encode("utf-8")
    value = os.environ.get(name)
    if value:
        return value.encode("utf-8")
    raise SecretUnavailable(name + " is not set; the platform must inject it")
