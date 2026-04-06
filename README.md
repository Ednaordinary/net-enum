# Networking scripts

This is my collection of random networking scripts. It started as just a brute force DNS enumerator, but also now has an unnecessarily fast port scanner. I've marked scripts that can pretty easily kill stuff with a *

## Convoy *

- Scans any CIDR IP range and port range using the low level XDP linux feature
- Millions of ports scanned per second with a single core
- `sudo convoy 0.0.0.0/0 443` or `sudo convoy 0.0.0.0/0 1 1000` for a range

## DNS Enum *

- Scans every permutation of A-Z and 0-9 on a DNS server
- ~3.8 Gibps with 10 processes
- Still slow due to exponential growth
- This is not an optimal approach if the DNS server has PTR records

## Port Scanner *

- Scans all non-dynamic ports on a specific /16 subnet in 36 minutes, or the first 1000 in 30 seconds
- ~2 Gibps, ~2 million connections, with 85 cores used (most networks cannot handle this)
