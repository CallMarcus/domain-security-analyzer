# Domain DNS Record Security Analyzer

This repository contains a Python script for assessing basic security
configurations of domain names. The tool performs DNS lookups, subdomain
enumeration, and HTTP checks to help identify potential configuration issues.

## Features

- Validates that required Python packages are available before running the
  analysis. If dependencies are missing the script prints the packages to
  install and exits.
- Looks up SPF, DKIM and DMARC TXT records.
- Retrieves SOA information for the parent domain including the primary
  nameserver and administrative contact.
- Discovers common subdomains and detects wildcard DNS entries. Known
  hosting provider patterns are matched from discovered CNAMEs.
- Checks if the domain is reachable over HTTP and whether it redirects to
  HTTPS, storing the full redirect chain.
- Processes multiple domains in parallel and outputs the results to a CSV file.

## Requirements

- Python 3.x
- [`dnspython`](https://pypi.org/project/dnspython/)
- [`requests`](https://pypi.org/project/requests/)

The script will alert you if these packages are missing:

```bash
$ python domain_analyzer.py
ERROR: Missing required Python packages!

Please install the following packages:
  - dnspython
  - requests
```

## Usage

Prepare a text file with one domain per line, for example `examples/domains.txt`:

```text
contoso.com
rzy.domain.com
```

Run the analyzer and specify the output CSV file:

```bash
python domain_analyzer.py examples/domains.txt report.csv
```

You can optionally set the number of parallel workers:

```bash
python domain_analyzer.py examples/domains.txt report.csv 20
```

The generated CSV includes the following columns:

- Domain
- Timestamp
- Parent Domain
- SOA Exists
- SOA Record
- Primary NS
- Admin Email
- SPF Exists
- SPF Record
- DKIM Exists
- DKIM Records
- DMARC Exists
- DMARC Record
- Discovered Subdomains
- CNAME Records
- Has Wildcard DNS
- Hosting Provider
- HTTP Accessible
- Redirects to HTTPS
- Final URL
- Redirect Chain
- HTTP Error

## Parked Domain CSV Generator

The `scripts/parked_domain_csv.py` helper script creates DNS change records for
locking down parked or non-mailing domains. Provide a text file of domains and
an output CSV path:

```bash
python scripts/parked_domain_csv.py examples/domains.txt parked_domains.csv
```

Pass `--dmarc-cname` to override the default DMARC CNAME target:

```bash
python scripts/parked_domain_csv.py examples/domains.txt parked_domains.csv --dmarc-cname reject.dmarc.contoso.com.
```

Each domain receives the following DNS entries:

- SPF record with `-all`
- Null MX record
- DKIM wildcard with an empty key
- DMARC CNAME pointing to a reject policy (customizable via `--dmarc-cname`)

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
