# Domain Security Analyzer

[![PyPI version](https://img.shields.io/pypi/v/domain-security-analyzer.svg)](https://pypi.org/project/domain-security-analyzer/)
[![Python versions](https://img.shields.io/pypi/pyversions/domain-security-analyzer.svg)](https://pypi.org/project/domain-security-analyzer/)
[![Downloads](https://img.shields.io/pypi/dm/domain-security-analyzer.svg)](https://pypi.org/project/domain-security-analyzer/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A comprehensive Python tool for analyzing domain security configurations including DNS records, email security policies, subdomain discovery, and **Subresource Integrity (SRI) scanning**. The tool performs parallel analysis of domain portfolios to identify potential security configuration issues and modern security compliance gaps.

## Features

### **Core Security Analysis**
- **Email Security**: Comprehensive SPF, DKIM, and DMARC record analysis
- **DNS Security**: SOA record validation, subdomain discovery, and wildcard DNS detection (filters wildcard-derived subdomains)
- **SSL/TLS Assessment**: HTTP to HTTPS redirect validation and certificate analysis
- **Hosting Intelligence**: Automatic hosting provider identification from CNAME patterns

### **🆕 Subresource Integrity (SRI) Scanning**
- **External Resource Detection**: Identifies JavaScript and CSS files loaded from external domains
- **SRI Coverage Analysis**: Calculates percentage of external resources with integrity attributes
- **Hash Algorithm Detection**: Identifies SHA-256, SHA-384, and SHA-512 usage
- **Supply Chain Security**: Helps assess protection against supply chain attacks
- **SecurityScorecard Alignment**: Matches new SRI scoring criteria for compliance reporting

### **Performance & Scalability**
- **Lightning-Fast Parallel Processing**: Configurable worker threads for large domain portfolios
- **Intelligent Resource Management**: Single HTTP request captures both redirect and SRI data
- **Memory Efficient**: Optimized HTML parsing with reasonable size limits
- **Robust Error Handling**: Graceful handling of network timeouts and parsing errors

### **Enterprise Features**
- **Comprehensive CSV Output**: 29+ data columns including all security metrics
- **Historical Tracking**: Timestamped results for trend analysis
- **Batch Processing**: Analyze hundreds of domains efficiently
- **Cross-Platform**: Works on Windows, Linux, and macOS

## Requirements

- **Python 3.7+**
- **Required Packages:**
  - [`dnspython`](https://pypi.org/project/dnspython/) - DNS query functionality
  - [`requests`](https://pypi.org/project/requests/) - HTTP requests and redirect analysis
  - [`beautifulsoup4`](https://pypi.org/project/beautifulsoup4/) - HTML parsing for SRI analysis

### **Installation**

Install from PyPI (recommended):

```bash
pip install domain-security-analyzer
```

This installs the dependencies automatically and adds the `domain-analyzer`
command to your `PATH`.

#### From source

```bash
git clone https://github.com/CallMarcus/domain-security-analyzer.git
cd domain-security-analyzer
pip install -e .
```

#### Dependencies only (running the script directly)

```bash
# Install required dependencies
pip install dnspython requests beautifulsoup4

# Or install all at once
pip install -r requirements.txt
```

When run as a script, the tool automatically validates dependencies and provides installation guidance:

```bash
$ python domain_analyzer.py
ERROR: Missing required Python packages!

Please install the following packages:
  - dnspython
  - beautifulsoup4

Installation command:
  pip install dnspython beautifulsoup4

Note: beautifulsoup4 is required for SRI (Subresource Integrity) analysis
```

## Usage

Prepare a text file with one domain per line, for example `examples/domains.txt`:

```text
contoso.com
rzy.domain.com
```

Run the analyzer and specify the output CSV file. If installed from PyPI, use the
`domain-analyzer` command:

```bash
domain-analyzer examples/domains.txt report.csv
```

You can optionally set the number of parallel workers:

```bash
domain-analyzer examples/domains.txt report.csv 20
```

The same interface is available via `python -m domain_security_analyzer` or, for
backward compatibility, by running the script directly:

```bash
python -m domain_security_analyzer examples/domains.txt report.csv
python domain_analyzer.py examples/domains.txt report.csv   # legacy shim
```

The generated CSV includes comprehensive security analysis with **29 columns**:

### **Domain & Infrastructure**
- Domain, Timestamp, Parent Domain
- SOA Exists, SOA Record, Primary NS, Admin Email
- Discovered Subdomains, CNAME Records
- Has Wildcard DNS, Hosting Provider
  - Note: When wildcard DNS is detected, subdomains whose answers match the wildcard baseline (A or CNAME) are suppressed to avoid listing non-existent subdomains. Explicit CNAMEs and A records differing from the wildcard baseline are included.

### **Email Security**
- SPF Exists, SPF Record
- DKIM Exists, DKIM Records  
- DMARC Exists, DMARC Record

### **Web Security**
- HTTP Accessible, Redirects to HTTPS
- Final URL, Redirect Chain, HTTP Error

### **🆕 Subresource Integrity (SRI)**
- **SRI Enabled** - Boolean indicating SRI implementation
- **Total External Resources** - Count of external JS/CSS files
- **Resources With SRI** - Count with integrity attributes
- **SRI Coverage %** - Percentage of protected resources (0-100%)
- **Missing SRI Count** - Unprotected external resources
- **SRI Algorithms Used** - Hash algorithms detected (sha256, sha384, sha512)
- **SRI Error** - Parsing errors or issues

### **Example SRI Results**
```csv
Domain,SRI Enabled,Total External Resources,Resources With SRI,SRI Coverage %,Missing SRI Count,SRI Algorithms Used
github.com,False,71,0,0.0,71,
stackoverflow.com,False,26,0,0.0,26,
```

## Security Scorecard Integration

This tool is designed to complement **SecurityScorecard** assessments by providing detailed SRI analysis that aligns with their updated scoring criteria. The SRI scanning helps identify:

- **Supply Chain Vulnerabilities**: External resources without integrity protection
- **Compliance Gaps**: Modern security practice adoption across domain portfolios  
- **Risk Prioritization**: Domains with high external resource usage requiring SRI implementation
- **Trend Analysis**: Historical SRI adoption progress over time

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

## Unsafe SRI Parser

Use `scripts/sri_parser.py` when you need a focused crawl that inventories
"unsafe" Subresource Integrity implementations called out by
[SecurityScorecard's guidance](https://support.securityscorecard.com/hc/en-us/articles/41067186972827-Unsafe-Implementation-of-Subresource-Integrity-SRI).
By default the scanner inspects only the requested page so the results mirror
SecurityScorecard's behaviour. The summary now also reports how many external
resources already include an `integrity` attribute. Add the `--crawl` flag to
follow same-origin links, inspect third-party JavaScript and CSS includes across
multiple pages, and report every resource that:

- Omits an `integrity` attribute entirely
- Supplies hashes that do not start with `sha256-`, `sha384-`, or `sha512-`
- Mixes valid and invalid hash values
- Loads over plain HTTP
- Uses a different origin without the required `crossorigin` attribute

The crawler also records any restrictive `Content-Security-Policy` headers so
you can tell whether a compensating control is in place.

```bash
# Human-readable output for the landing page only
python scripts/sri_parser.py https://example.com

# List every external include that already uses SRI
python scripts/sri_parser.py https://example.com --list-sri

# JSON report with a deeper crawl (depth 2, up to 50 pages)
python scripts/sri_parser.py https://example.com --crawl --max-depth 2 --max-pages 50 --json
```

The report lists the affected page, resource URL, integrity/crossorigin values,
and short reason codes for each unsafe include. When `--list-sri` is supplied the
output also enumerates each external script and stylesheet that defines an
`integrity` attribute.

## Documentation

### **Reference Guides**
- **[SRI Reference](docs/sri-reference.md)** - Complete guide to Subresource Integrity analysis
- **[CSV Output Reference](docs/csv-output-reference.md)** - Detailed column descriptions and data interpretation
- **[DMARC Reference](docs/dmarc-reference.md)** - DMARC policy analysis and configuration
- **[SPF Reference](docs/spf-reference.md)** - SPF record validation and best practices
- **[DKIM Reference](docs/dkim-reference.md)** - DKIM selector and key analysis

### **Advanced Usage**

#### **Large-Scale Domain Analysis**
```bash
# High-performance analysis of 1000+ domains
python domain_analyzer.py enterprise_domains.txt full_report.csv 50

# Memory-efficient processing
python domain_analyzer.py huge_list.txt results.csv 20
```

#### **Targeted SRI Assessment**
```bash
# Focus on domains with external resources
grep -v "0,0,0.0,0" results.csv > domains_with_resources.csv

# Find domains with SRI gaps
awk -F',' '$24=="True" && $27<100 {print $1}' results.csv
```

## Performance Characteristics

- **Throughput**: 100-500 domains/minute (depends on network and worker count)
- **Memory Usage**: ~50MB base + 1-2MB per concurrent worker
- **Network Efficiency**: Single HTTP request captures both redirect and SRI data
- **Scalability**: Linear performance scaling with worker count

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.
### Optional flags

- `--include-wildcard-matches`
  - Include subdomains whose DNS answers match the wildcard baseline (A or CNAME).
  - Default behavior filters these out to avoid listing non-existent subdomains.

- `--filtered-subdomains-file <path>`
  - Writes a separate CSV with subdomains excluded due to wildcard filtering.
  - Columns: `Domain`, `Filtered Subdomains` (comma-separated).

Examples:

```bash
# Include wildcard-matched subdomains
python domain_analyzer.py examples/domains.txt report.csv --include-wildcard-matches

# Save filtered subdomains to a separate CSV while keeping main CSV schema unchanged
python domain_analyzer.py examples/domains.txt report.csv --filtered-subdomains-file filtered.csv

# Combine with explicit worker count
python domain_analyzer.py examples/domains.txt report.csv 20 --filtered-subdomains-file filtered.csv
```

## Wildcard Filtering

- Default behavior filters subdomains that only resolve due to wildcard DNS. The analyzer establishes a baseline by querying a random label and comparing A and CNAME answers.
- Inclusion rules:
  - Include explicit CNAMEs unless they match the wildcard CNAME baseline.
  - Include A records when they differ from the wildcard A baseline.
- Use `--include-wildcard-matches` to disable filtering and include all matches.
- Use `--filtered-subdomains-file <path>` to export filtered items for auditing.
- Caveat: If an explicit host’s A rrset is identical to the wildcard A baseline, it will be filtered by default. Use `--include-wildcard-matches` or audit via the filtered CSV if needed.
