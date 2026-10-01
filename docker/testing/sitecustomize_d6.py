"""Qualification image only: repeat upstream injection in every real worker."""
import os
import sys

if sys.orig_argv[1:] == ['-m', 'exitlane.container_entrypoint', 'worker']:
    try:
        from _exitlane_d6_upstream import install
        install()
    except Exception:  # noqa: BLE001 - every fixture initialization error must stop the worker
        # Python may ignore ordinary sitecustomize exceptions. Never fall back
        # to commercial APIs when the qualification fixture cannot initialize.
        os.write(2, b'qualification_upstream_initialization_failed\n')
        os._exit(78)
