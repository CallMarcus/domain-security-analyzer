import sys
from datetime import datetime

# Check for required modules before proceeding
def check_required_modules():
    """Check if required modules are installed and provide installation instructions if missing."""
    missing_modules = []
    
    try:
        import dns.resolver
    except ImportError:
        missing_modules.append('dnspython')
    
    try:
        import requests
    except ImportError:
        missing_modules.append('requests')
    
    if missing_modules:
        print("ERROR: Missing required Python packages!")
        print("\nPlease install the following packages:")
        for module in missing_modules:
            print(f"  - {module}")
        
        print("\nInstallation command:")
        print(f"  pip install {' '.join(missing_modules)}")
        print("\nOr if using pip3:")
        print(f"  pip3 install {' '.join(missing_modules)}")
        print("\nIf using a virtual environment, activate it first and then run the pip command.")
        sys.exit(1)

# Check modules before importing
check_required_modules()

import dns.resolver
import requests
import concurrent.futures
import csv
from typing import Dict, List, Optional

class DomainAnalyzer:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        
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
        cname_records = {}
        
        # Check common subdomains
        for subdomain in self.common_subdomains:
            fqdn = f"{subdomain}.{domain}"
            try:
                # Check for A record
                a_records = self.get_dns_record(fqdn, 'A')
                if a_records:
                    found_subdomains.add(fqdn)
                
                # Check for CNAME record
                cname = self.get_dns_record(fqdn, 'CNAME')
                if cname:
                    found_subdomains.add(fqdn)
                    cname_records[fqdn] = cname[0]
            except:
                continue

        # Check for wildcard DNS
        try:
            random_sub = f"wildcard-test-{datetime.now().strftime('%Y%m%d%H%M%S')}.{domain}"
            wildcard_records = self.get_dns_record(random_sub, 'A')
            has_wildcard = bool(wildcard_records)
        except:
            has_wildcard = False

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
            "hosting_provider": hosting_provider
        }

    def check_http_redirect(self, domain: str) -> Dict:
        """Check for insecure HTTP to HTTPS redirects."""
        result = {
            "http_accessible": False,
            "redirects_to_https": False,
            "final_url": None,
            "error": None,
            "redirect_chain": []
        }

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
            
        except requests.exceptions.RequestException as e:
            result["error"] = str(e)

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
        
        return {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "soa": self.get_soa_record(domain),
            "spf": self.check_spf(domain),
            "dkim": self.check_dkim(domain),
            "dmarc": self.check_dmarc(domain),
            "subdomains": subdomain_info,
            "http_redirect": self.check_http_redirect(domain)
        }

def analyze_domains_from_file(input_file: str, output_file: str, max_workers: int = 10):
    """Analyze multiple domains from a file and save results to CSV."""
    
    # Read domains from input file
    with open(input_file, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    total_domains = len(domains)
    completed = 0
    
    def analyze_single_domain(domain: str) -> Dict:
        """Worker function for parallel processing"""
        nonlocal completed
        analyzer = DomainAnalyzer()  # Create new instance for thread safety
        try:
            result = analyzer.analyze_domain(domain)
        except Exception as e:
            result = {
                "domain": domain,
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
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
                results.append({
                    "domain": domain,
                    "timestamp": datetime.now().isoformat(),
                    "error": str(e)
                })

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
            'HTTP Error'
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
                ','.join([f"{k}:{v}" for k,v in r['subdomains']['cname_records'].items()]),
                r['subdomains']['has_wildcard_dns'],
                r['subdomains']['hosting_provider'],
                r['http_redirect']['http_accessible'],
                r['http_redirect']['redirects_to_https'],
                r['http_redirect']['final_url'],
                ' -> '.join(r['http_redirect'].get('redirect_chain', [])),
                r['http_redirect']['error']
            ])

if __name__ == "__main__":
    import platform
    import os
    
    # Windows-specific console configuration
    if platform.system() == 'Windows':
        try:
            import colorama
            colorama.init()  # Initialize colorama for Windows color support
        except ImportError:
            pass  # colorama not installed, colors won't work
        
        # Try to set console to UTF-8 mode
        try:
            os.system('chcp 65001 > nul')
        except:
            pass

    if len(sys.argv) < 3:
        print("Usage: python domain_analyzer.py input_file.txt output_file.csv [max_workers]")
        print("max_workers: Optional, default is 10")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    # Adjust default workers based on OS and CPU count
    default_workers = min(10, (os.cpu_count() or 4) * 2)
    max_workers = int(sys.argv[3]) if len(sys.argv) > 3 else default_workers
    
    # Ensure input/output files use proper path separators
    input_file = os.path.normpath(input_file)
    output_file = os.path.normpath(output_file)
    
    print(f"\nStarting domain analysis:")
    print(f"Operating System: {platform.system()} {platform.release()}")
    print(f"Input file: {input_file}")
    print(f"Output file: {output_file}")
    print(f"Workers: {max_workers}\n")
    
    try:
        analyze_domains_from_file(input_file, output_file, max_workers)
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user. Partial results may have been saved.")
    except Exception as e:
        print(f"\nError during analysis: {str(e)}")
        sys.exit(1)
