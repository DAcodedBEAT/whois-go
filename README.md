WHOIS Go client
---------------

A simple WHOIS client in Go that performs WHOIS lookups and follows redirects.

## Build
```sh
go build -o whois-go
```

## Usage
```sh
./whois-go example.com           # Basic WHOIS lookup
./whois-go -h whois.verisign-grs.com example.com  # Custom WHOIS server
./whois-go -p 43 example.com     # Custom port
./whois-go -i example.com        # Show redirects
```

## Flags
- `-h <server>`: WHOIS server (default: `whois.iana.org`)
- `-p <port>`: Port number (default: `43`)
- `-i`: Show WHOIS redirects

## Example Output
```
WHOIS response for example.com:
Domain Name: EXAMPLE.COM
Registry Domain ID: 2336799_DOMAIN_COM-VRSN
...
```
