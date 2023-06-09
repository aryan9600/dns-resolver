# dns-resolver

dns-resolver is a toy DNS resolver. It can handle A, NS, CNAME and TXT records.
It's mainly written by understanding the contents of https://implement-dns.wizardzines.com/book/intro.html
and https://datatracker.ietf.org/doc/html/rfc1035. The primary goal of this project
is to understand how DNS works from the ground up and brush up on my Rust skills.

## Usage

```bash
❯ cargo run --bin client google.com TXT

Querying 198.41.0.4 for google.com about TXT type
Querying 192.12.94.30 for google.com about TXT type
Querying 216.239.34.10 for google.com about TXT type
answer(s): ["atlassian-domain-verification=5YjTmWmjI92ewqkx2oXmBaD60Td9zWon9r6eakvHX6B77zzkFQto8PQ9QsKnbf4I", "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95", "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8=", "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB", "v=spf1 include:_spf.google.com ~all", "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"]
```

```bash
❯ cargo run --bin client google.com NS

Querying 198.41.0.4 for google.com about NS type
Querying 192.12.94.30 for google.com about NS type
Querying 216.239.34.10 for google.com about NS type
answer(s): ["ns1.google.com", "ns3.google.com", "ns4.google.com", "ns2.google.com"]
```

```bash
❯ cargo run --bin client google.com A

Querying 198.41.0.4 for google.com about A type
Querying 192.12.94.30 for google.com about A type
Querying 216.239.34.10 for google.com about A type
answer(s): ["74.125.24.101", "74.125.24.139", "74.125.24.138", "74.125.24.113", "74.125.24.102", "74.125.24.100"]
```

```bash
❯ cargo run --bin client www.github.com CNAME

Querying 198.41.0.4 for www.github.com about CNAME type
Querying 192.12.94.30 for www.github.com about CNAME type
Querying 205.251.193.165 for www.github.com about CNAME type
answer(s): ["github.com"]
```
