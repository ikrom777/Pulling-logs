# # SSH Log Analyser

A small Python tool that reads SSH authentication log lines (syslog format), detects suspicious activity, and prints a plain-text report. It works as a command-line tool and as a Python module.

It looks for three things:

\- \*\*Compromised logins:\*\* an IP that failed to log in several times within a short window and was then followed by a successful login.

\- \*\*Brute-force bursts:\*\* an IP with many failed logins inside a short time window, whether or not it eventually got in.

\- \*\*Top offenders:\*\* the IPs with the most failed logins overall, each shown with its hostname (from a reverse DNS lookup) when one exists.

\## Requirements

\- Python 3.9 or newer (standard library only)

\- pytest and pytest-cov for the tests

\- Network access for the hostname lookups (the report still works offline, it just shows \`no hostname\`)

\## Quick start

\### Command line

\`\`\`

python pullinglogs.py sample\_auth.log

python pullinglogs.py sample\_auth.log --threshold 3 --window 10 --top 5

\`\`\`

A sample log file, \`sample\_auth.log\`, is included in the repository.

\| Option \| Meaning \| Default \|

\|---\|---\|---\|

\| \`logfile\` \| Path to the log file \| required \|

\| \`-t\`, \`--threshold\` \| Failed logins needed to flag a compromise or a brute-force burst \| 2 \|

\| \`-w\`, \`--window\` \| Time window in minutes in which the failures must happen \| 5 \|

\| \`-y\`, \`--year\` \| Year added to timestamps \| 2026 \|

\| \`-n\`, \`--top\` \| Number of top offenders to list \| 3 \|

Show all options with:

\`\`\`

python pullinglogs.py -h

\`\`\`

\### As a module

\`\`\`python

from pullinglogs import parse\_log, build\_report

with open("auth.log") as f:

   entries = parse\_log(f)

print(build\_report(entries, threshold=5, n=3))

\`\`\`

Note that the module function \`build\_report\` defaults to a threshold of 5, while the command line defaults to 2.

\## Input format

The parser expects sshd lines like these:

\`\`\`

Oct 25 03:12:01 server sshd\[1234\]: Failed password for root from 203.0.113.5 port 52341 ssh2

Oct 25 03:12:05 server sshd\[1234\]: Failed password for invalid user admin from 198.51.100.7 port 40022 ssh2

Oct 25 03:15:44 server sshd\[1301\]: Accepted
