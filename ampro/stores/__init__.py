"""Shared state backends for running ampro on several workers / machines.

Every stateful component in ampro sits behind a small protocol with a
bounded in-memory default (correct for a single process).  The modules
here implement those protocols over a store that every worker shares:

* :mod:`ampro.stores.redis` — Redis (``pip install 'ampro[redis]'``).

See ``docs/SCALING.md`` for the full inventory.
"""
