# Test fixtures

`logs/` holds small log files that tests copy into a temporary source path.
They are stored with LF line endings (see `.gitattributes`) because tests
compare raw lines byte for byte.

| File | Source kind | What it contains |
|------|-------------|------------------|
| `ssh_bruteforce.log` | `ssh_auth` | 6 failed logins from 203.0.113.50 in 50 s (R1 fires: threshold 5 in 5 min), one accepted login from 198.51.100.20, and two lines that are not logins. Times are local America/Indiana/Indianapolis (10:00 local = 14:00Z). |
