# dns-resolver

dns-resolver is a toy DNS resolver. It can handle A, NS, CNAME and TXT records.
Its a recursive resolver that can be used as DNS client or server. The server supports
caching via a fixed size LRU cache.

It's mainly written by understanding the contents of https://implement-dns.wizardzines.com/book/intro.html
and https://datatracker.ietf.org/doc/html/rfc1035. The primary goal of this project
is to understand how DNS works from the ground up and brush up on my Rust skills.

## Usage

### Client

Fetch the A records for google.com:

```bash
❯ cargo run --bin client google.com A

Querying 198.41.0.4 for google.com about record type A
Querying 192.12.94.30 for google.com about record type A
Querying 216.239.34.10 for google.com about record type A
answer(s): ["142.250.76.174"]
```

Fetch the CNAME records for www.github.com:

```bash
❯ cargo run --bin client www.github.com CNAME

Querying 198.41.0.4 for www.github.com about record type CNAME
Querying 192.12.94.30 for www.github.com about record type CNAME
Querying 205.251.193.165 for www.github.com about record type CNAME
answer(s): ["github.com"]
```

### Server

Run the server:

```bash
❯ cargo run --bin server
```

Open another terminal window and use `dig` to access the server:

```bash
❯ dig @127.0.0.1 -p 3500 google.com A

; <<>> DiG 9.10.6 <<>> @127.0.0.1 -p 3500 google.com A
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 34233
;; flags: qr aa; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.                    IN      A

;; ANSWER SECTION:
google.com.             300     IN      A       142.250.67.206

;; Query time: 305 msec
;; SERVER: 127.0.0.1#3500(127.0.0.1)
;; WHEN: Mon Jan 08 01:37:32 IST 2024
;; MSG SIZE  rcvd: 44
```
