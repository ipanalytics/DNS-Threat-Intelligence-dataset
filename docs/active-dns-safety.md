# Active DNS Safety

The resolver module performs DNS lookups only. It supports timeout, retry,
cache-friendly usage, conservative query rounds, and rate limits. GitHub
Actions must not perform internet-wide DNS or resolver scans.

