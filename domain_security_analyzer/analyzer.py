"""Core domain analysis logic.

Contains :class:`DomainAnalyzer` and :func:`analyze_domains_from_file`, the
importable API for the package. The command-line interface lives in
``domain_security_analyzer.cli``.
"""

import concurrent.futures
import csv
from datetime import datetime
from typing import Dict, List, Optional
from urllib.parse import urlparse

import dns.resolver
import requests
from bs4 import BeautifulSoup


class DomainAnalyzer:
    def __init__(self, include_wildcard_matches: bool = False, collect_filtered: bool = False):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        self.include_wildcard_matches = include_wildcard_matches
        self.collect_filtered = collect_filtered

        # Common subdomain prefixes to check
        self.common_subdomains = [
            'www', 'mail', 'webmail', 'email', 'remote', 'portal', 'owa',
            'vpn', 'mta', 'mx', 'imap', 'smtp', 'pop', 'cp', 'cpanel',
            'webdisk', 'whm', 'ns1', 'ns2', 'autodiscover', 'autoconfig',
            'admin', 'cloud', 'dev', 'ftp', 'test', 'staging'
        ]

        # Common hosting providers' default records
        self.hosting_patterns = {
            'GoDaddy': ['.secureserver.net'],
            'BlueHost': ['.bluehost.com'],
            'HostGator': ['.hostgator.com'],
            'DreamHost': ['.dreamhost.com'],
            'NameCheap': ['.registrar-servers.com'],
            'OVH': ['.ovh.net'],
            'AWS': ['.amazonaws.com'],
            'Google Cloud': ['.googlehosted.com'],
            'Microsoft Azure': ['.azurewebsites.net'],
            'Cloudflare': ['.cloudflare.net']
        }

    def get_dns_record(self, domain: str, record_type: str) -> Optional[List[str]]:
        """Query DNS records of specified type for a domain."""
        try:
            # Try with default resolver first
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except dns.exception.Timeout:
            # On timeout, try with system DNS servers
            try:
                # Get system DNS servers (useful especially on Windows)
                system_resolver = dns.resolver.Resolver(configure=True)
                system_resolver.timeout = 3
                system_resolver.lifetime = 3
                answers = system_resolver.resolve(domain, record_type)
                return [str(rdata) for rdata in answers]
            except:
                return None
        except Exception as e:
            if "SERVFAIL" in str(e):
                return None  # Common on Windows when DNS server is unreachable
            return f"Error: {str(e)}"

    def check_spf(self, domain: str) -> Dict:
        """Check SPF record for domain."""
        records = self.get_dns_record(domain, 'TXT')
        if not records:
            return {"exists": False, "record": None}

        spf_records = [r for r in records if r.startswith('"v=spf1')]
        if not spf_records:
            return {"exists": False, "record": None}

        return {
            "exists": True,
            "record": spf_records[0],
            "multiple_records": len(spf_records) > 1
        }

    def check_dkim(self, domain: str, selectors: List[str] = ['default', 'google', 'dkim', 'k1']) -> Dict:
        """Check DKIM record for domain with multiple common selectors."""
        results = []
        for selector in selectors:
            dkim_domain = f"{selector}._domainkey.{domain}"
            record = self.get_dns_record(dkim_domain, 'TXT')
            if record:
                results.append({
                    "selector": selector,
                    "record": record[0]
                })

        return {
            "exists": bool(results),
            "records": results
        }

    def check_dmarc(self, domain: str) -> Dict:
        """Check DMARC record for domain."""
        dmarc_domain = f"_dmarc.{domain}"
        record = self.get_dns_record(dmarc_domain, 'TXT')

        return {
            "exists": bool(record),
            "record": record[0] if record else None
        }

    def discover_subdomains(self, domain: str) -> Dict:
        """Discover subdomains using various methods."""
        found_subdomains = set()
        filtered_subdomains = set()
        cname_records = {}

        # Helper to normalize DNS rrsets for comparison
        def _norm_rrset(rrset: Optional[List[str]]) -> Optional[tuple]:
            if not rrset:
                return None
            try:
                return tuple(sorted(str(r).strip().lower() for r in rrset))
            except Exception:
                return tuple(sorted(rrset))

        # Establish wildcard baseline answers (if any)
        try:
            random_sub = f"wildcard-test-{datetime.now().strftime('%Y%m%d%H%M%S')}.{domain}"
            wildcard_a = self.get_dns_record(random_sub, 'A')
            wildcard_cname = self.get_dns_record(random_sub, 'CNAME')
            has_wildcard = bool(wildcard_a or wildcard_cname)
            wildcard_a_norm = _norm_rrset(wildcard_a)
            wildcard_cname_norm = _norm_rrset(wildcard_cname)
        except Exception:
            has_wildcard = False
            wildcard_a_norm = None
            wildcard_cname_norm = None

        # Check common subdomains
        for subdomain in self.common_subdomains:
            fqdn = f"{subdomain}.{domain}"
            try:
                # Prefer explicit CNAMEs
                cname = self.get_dns_record(fqdn, 'CNAME')
                a_records = self.get_dns_record(fqdn, 'A')

                include = False

                if cname:
                    # Include CNAMEs unless they match the wildcard CNAME baseline
                    if has_wildcard and _norm_rrset(cname) == wildcard_cname_norm and not self.include_wildcard_matches:
                        include = False
                        if self.collect_filtered:
                            filtered_subdomains.add(fqdn)
                    else:
                        include = True
                        cname_records[fqdn] = cname[0]
                elif a_records:
                    # If wildcard is present, suppress A-only results that
                    # exactly match the wildcard baseline to avoid false positives
                    if has_wildcard:
                        if self.include_wildcard_matches or _norm_rrset(a_records) != wildcard_a_norm:
                            include = True
                        else:
                            if self.collect_filtered:
                                filtered_subdomains.add(fqdn)
                    else:
                        include = True

                if include:
                    found_subdomains.add(fqdn)
            except Exception:
                continue

        # Identify hosting provider
        hosting_provider = None
        for provider, patterns in self.hosting_patterns.items():
            for pattern in patterns:
                if any(pattern in cname for cname in cname_records.values()):
                    hosting_provider = provider
                    break
            if hosting_provider:
                break

        return {
            "subdomains": list(found_subdomains),
            "cname_records": cname_records,
            "has_wildcard_dns": has_wildcard,
            "hosting_provider": hosting_provider,
            "filtered_subdomains": list(filtered_subdomains)
        }

    def check_http_redirect(self, domain: str) -> "tuple[Dict, str]":
        """Check for insecure HTTP to HTTPS redirects and capture HTML content."""
        result = {
            "http_accessible": False,
            "redirects_to_https": False,
            "final_url": None,
            "error": None,
            "redirect_chain": []
        }
        html_content = ""

        try:
            http_url = f"http://{domain}"
            response = requests.get(http_url, allow_redirects=True, timeout=10)

            result["http_accessible"] = True
            result["final_url"] = response.url
            result["redirects_to_https"] = response.url.startswith("https://")

            # Capture redirect chain
            if response.history:
                result["redirect_chain"] = [r.url for r in response.history]
                result["redirect_chain"].append(response.url)

            # Capture HTML content for SRI analysis (limit to reasonable size)
            if response.headers.get('content-type', '').startswith('text/html'):
                html_content = response.text[:500000]  # Limit to 500KB to avoid memory issues

        except requests.exceptions.RequestException as e:
            result["error"] = str(e)

        return result, html_content

    def _is_external_resource(self, url: str, domain: str) -> bool:
        """Check if a resource URL is external to the given domain."""
        if not url:
            return False

        # Handle relative URLs
        if not url.startswith(('http://', 'https://')):
            return False

        parsed_url = urlparse(url)
        resource_domain = parsed_url.netloc.lower()

        # Remove www prefix for comparison
        main_domain = domain.lower().replace('www.', '')
        resource_domain = resource_domain.replace('www.', '')

        return resource_domain != main_domain

    def _extract_hash_algorithm(self, integrity_attr: str) -> str:
        """Extract hash algorithm from integrity attribute."""
        if not integrity_attr:
            return None

        # integrity="sha384-..." or "sha256-..." etc.
        if integrity_attr.startswith('sha256-'):
            return 'sha256'
        elif integrity_attr.startswith('sha384-'):
            return 'sha384'
        elif integrity_attr.startswith('sha512-'):
            return 'sha512'
        else:
            return 'unknown'

    def check_sri(self, domain: str, html_content: str) -> Dict:
        """Analyze Subresource Integrity implementation from HTML content."""
        result = {
            "sri_enabled": False,
            "total_external_resources": 0,
            "resources_with_sri": 0,
            "sri_coverage_percentage": 0,
            "missing_sri_count": 0,
            "sri_algorithms_used": set(),
            "error": None
        }

        if not html_content:
            result["error"] = "No HTML content available"
            return result

        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            external_resources = []

            # Find external scripts
            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if self._is_external_resource(src, domain):
                    external_resources.append({
                        'type': 'script',
                        'src': src,
                        'integrity': script.get('integrity'),
                        'crossorigin': script.get('crossorigin')
                    })

            # Find external stylesheets
            for link in soup.find_all('link', href=True):
                if link.get('rel') == ['stylesheet'] or 'stylesheet' in (link.get('rel') or []):
                    href = link.get('href')
                    if self._is_external_resource(href, domain):
                        external_resources.append({
                            'type': 'stylesheet',
                            'src': href,
                            'integrity': link.get('integrity'),
                            'crossorigin': link.get('crossorigin')
                        })

            # Analyze SRI implementation
            result["total_external_resources"] = len(external_resources)

            for resource in external_resources:
                if resource['integrity']:
                    result["resources_with_sri"] += 1
                    algorithm = self._extract_hash_algorithm(resource['integrity'])
                    if algorithm:
                        result["sri_algorithms_used"].add(algorithm)

            result["missing_sri_count"] = result["total_external_resources"] - result["resources_with_sri"]

            if result["total_external_resources"] > 0:
                result["sri_coverage_percentage"] = round(
                    (result["resources_with_sri"] / result["total_external_resources"]) * 100, 1
                )
                result["sri_enabled"] = result["resources_with_sri"] > 0

            # Convert set to sorted list for CSV output
            result["sri_algorithms_used"] = sorted(list(result["sri_algorithms_used"]))

        except Exception as e:
            result["error"] = f"SRI parsing error: {str(e)}"

        return result

    def get_parent_domain(self, domain: str) -> str:
        """Extract parent domain from subdomain (e.g., www.example.com -> example.com)."""
        parts = domain.split('.')
        if len(parts) <= 2:
            return domain  # Already a parent domain

        # Handle common TLDs and country codes
        # For simplicity, assume last two parts are the parent domain
        # This works for most cases like .com, .org, .co.uk, etc.
        return '.'.join(parts[-2:])

    def get_soa_record(self, domain: str) -> Dict:
        """Get SOA (Start of Authority) record for the parent domain."""
        parent_domain = self.get_parent_domain(domain)

        try:
            soa_records = self.get_dns_record(parent_domain, 'SOA')
            if not soa_records:
                return {"exists": False, "parent_domain": parent_domain, "record": None}

            # Parse SOA record components - only extract DNS names
            soa_parts = soa_records[0].split()
            if len(soa_parts) >= 2:
                # Only include the primary nameserver and admin email (first two fields)
                dns_names_only = f"{soa_parts[0]} {soa_parts[1]}"
                return {
                    "exists": True,
                    "parent_domain": parent_domain,
                    "record": dns_names_only,
                    "primary_ns": soa_parts[0],
                    "admin_email": soa_parts[1]
                }
            else:
                return {
                    "exists": True,
                    "parent_domain": parent_domain,
                    "record": soa_records[0],
                    "primary_ns": None,
                    "admin_email": None
                }
        except Exception as e:
            return {
                "exists": False,
                "parent_domain": parent_domain,
                "record": None,
                "error": str(e)
            }

    def analyze_domain(self, domain: str) -> Dict:
        """Perform complete analysis of a domain."""
        subdomain_info = self.discover_subdomains(domain)

        # Get HTTP redirect info and HTML content in one request
        http_redirect_info, html_content = self.check_http_redirect(domain)

        # Analyze SRI using the captured HTML content
        sri_info = self.check_sri(domain, html_content)

        return {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "soa": self.get_soa_record(domain),
            "spf": self.check_spf(domain),
            "dkim": self.check_dkim(domain),
            "dmarc": self.check_dmarc(domain),
            "subdomains": subdomain_info,
            "http_redirect": http_redirect_info,
            "sri": sri_info
        }


def analyze_domains_from_file(input_file: str, output_file: str, max_workers: int = 10, *, include_wildcard_matches: bool = False, filtered_subdomains_file: Optional[str] = None):
    """Analyze multiple domains from a file and save results to CSV."""

    # Read domains from input file
    with open(input_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    total_domains = len(domains)
    completed = 0

    def analyze_single_domain(domain: str) -> Dict:
        """Worker function for parallel processing"""
        nonlocal completed
        analyzer = DomainAnalyzer(include_wildcard_matches=include_wildcard_matches, collect_filtered=bool(filtered_subdomains_file))  # Create new instance for thread safety
        try:
            result = analyzer.analyze_domain(domain)
        except Exception as e:
            # Create error result with all required fields for CSV
            result = {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "error": str(e),
                "soa": {"exists": False, "parent_domain": domain, "record": None, "primary_ns": None, "admin_email": None},
                "spf": {"exists": False, "record": None},
                "dkim": {"exists": False, "records": []},
                "dmarc": {"exists": False, "record": None},
                "subdomains": {"subdomains": [], "cname_records": {}, "has_wildcard_dns": False, "hosting_provider": None, "filtered_subdomains": []},
                "http_redirect": {"http_accessible": False, "redirects_to_https": False, "final_url": None, "error": str(e), "redirect_chain": []},
                "sri": {"sri_enabled": False, "total_external_resources": 0, "resources_with_sri": 0, "sri_coverage_percentage": 0, "missing_sri_count": 0, "sri_algorithms_used": [], "error": "Domain analysis failed"}
            }

        completed += 1
        print(f"Progress: {completed}/{total_domains} domains analyzed ({(completed/total_domains)*100:.1f}%)")
        return result

    results = []
    print(f"Starting analysis of {total_domains} domains using {max_workers} parallel workers...")

    # Use ThreadPoolExecutor for parallel processing
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {executor.submit(analyze_single_domain, domain): domain for domain in domains}

        for future in concurrent.futures.as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(f"Error analyzing {domain}: {str(e)}")
                # Create error result with all required fields for CSV
                error_result = {
                    "domain": domain,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e),
                    "soa": {"exists": False, "parent_domain": domain, "record": None, "primary_ns": None, "admin_email": None},
                    "spf": {"exists": False, "record": None},
                    "dkim": {"exists": False, "records": []},
                    "dmarc": {"exists": False, "record": None},
                    "subdomains": {"subdomains": [], "cname_records": {}, "has_wildcard_dns": False, "hosting_provider": None},
                    "http_redirect": {"http_accessible": False, "redirects_to_https": False, "final_url": None, "error": str(e), "redirect_chain": []},
                    "sri": {"sri_enabled": False, "total_external_resources": 0, "resources_with_sri": 0, "sri_coverage_percentage": 0, "missing_sri_count": 0, "sri_algorithms_used": [], "error": "Domain analysis failed"}
                }
                results.append(error_result)

    # Write results to CSV
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        # Write header
        writer.writerow([
            'Domain',
            'Timestamp',
            'Parent Domain',
            'SOA Exists',
            'SOA Record',
            'Primary NS',
            'Admin Email',
            'SPF Exists',
            'SPF Record',
            'DKIM Exists',
            'DKIM Records',
            'DMARC Exists',
            'DMARC Record',
            'Discovered Subdomains',
            'CNAME Records',
            'Has Wildcard DNS',
            'Hosting Provider',
            'HTTP Accessible',
            'Redirects to HTTPS',
            'Final URL',
            'Redirect Chain',
            'HTTP Error',
            'SRI Enabled',
            'Total External Resources',
            'Resources With SRI',
            'SRI Coverage %',
            'Missing SRI Count',
            'SRI Algorithms Used',
            'SRI Error'
        ])

        # Write results
        for r in results:
            writer.writerow([
                r['domain'],
                r['timestamp'],
                r['soa']['parent_domain'],
                r['soa']['exists'],
                r['soa'].get('record'),
                r['soa'].get('primary_ns'),
                r['soa'].get('admin_email'),
                r['spf']['exists'],
                r['spf'].get('record'),
                r['dkim']['exists'],
                ';'.join([f"{rec['selector']}:{rec['record']}" for rec in r['dkim']['records']]) if r['dkim']['records'] else '',
                r['dmarc']['exists'],
                r['dmarc'].get('record'),
                ','.join(r['subdomains']['subdomains']),
                ','.join([f"{k}:{v}" for k, v in r['subdomains']['cname_records'].items()]),
                r['subdomains']['has_wildcard_dns'],
                r['subdomains']['hosting_provider'],
                r['http_redirect']['http_accessible'],
                r['http_redirect']['redirects_to_https'],
                r['http_redirect']['final_url'],
                ' -> '.join(r['http_redirect'].get('redirect_chain', [])),
                r['http_redirect']['error'],
                r['sri']['sri_enabled'],
                r['sri']['total_external_resources'],
                r['sri']['resources_with_sri'],
                r['sri']['sri_coverage_percentage'],
                r['sri']['missing_sri_count'],
                ','.join(r['sri']['sri_algorithms_used']) if r['sri']['sri_algorithms_used'] else '',
                r['sri']['error']
            ])

    # Optionally write filtered subdomains to a separate CSV
    if filtered_subdomains_file:
        with open(filtered_subdomains_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Domain', 'Filtered Subdomains'])
            for r in results:
                filtered = r.get('subdomains', {}).get('filtered_subdomains', [])
                if filtered:
                    writer.writerow([r['domain'], ','.join(filtered)])
