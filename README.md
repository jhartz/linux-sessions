# linux-sessions

Find the timestamps of recent user sessions on a Linux box by reading from /var/log/wtmp.

**Why?** *Isn't this already handled by `last`?* I was upset that the output of `last` wasn't easily parseable by shell scripts, so I wrote this instead, which is more flexible for my scripting use cases.

**Usage:** `sessions [options] <username>`

- `-f, --format <fmt>`: The [strftime](https://linux.die.net/man/3/strftime) format to use to print out timestamps.
- `-a, --active`: Only print timestamps for sessions that are currently active.
- `-i, --inactive`: Only print timestamps for sessions that are no longer active.
- `-n, --num <num>`: Maximum number of timestamps to print.
- `-t, --after <ts>`: Only print timestamps after the unix timestamp `<ts>`.
- `-b, --before <ts>`: Only print timestamps before the unix timestamp `<ts>`.
- `-p, --print-extra`: Print extra information with each timestamp.
- `-h, --help`: Print a usage message.
