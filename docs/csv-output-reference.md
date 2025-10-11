# CSV Output Reference

## Overview

The Domain Security Analyzer generates comprehensive CSV reports with **29 columns** of security analysis data. This reference provides detailed descriptions of each column, data types, and interpretation guidelines.

## CSV Structure

### File Format
- **Encoding**: UTF-8
- **Delimiter**: Comma (`,`)
- **Header Row**: Always included
- **Quoting**: Automatic for fields containing commas/quotes

### Sample Output
```csv
Domain,Timestamp,Parent Domain,SOA Exists,SRI Enabled,Total External Resources,SRI Coverage %...
github.com,2025-01-15T10:30:45.123456,github.com,True,False,71,0.0...
```

Optional auxiliary output (when `--filtered-subdomains-file` is used):

```csv
Domain,Filtered Subdomains
example.com,www.example.com,blog.example.com
```

## Column Reference

### **Basic Domain Information**

| Column | Type | Description | Example Values |
|--------|------|-------------|----------------|
| `Domain` | String | Target domain being analyzed | `github.com`, `www.example.com` |
| `Timestamp` | ISO DateTime | Analysis execution time | `2025-01-15T10:30:45.123456` |
| `Parent Domain` | String | Root domain (removes subdomains) | `github.com` (from `www.github.com`) |

### **DNS Authority Information**

| Column | Type | Description | Example Values |
|--------|------|-------------|----------------|
| `SOA Exists` | Boolean | Start of Authority record found | `True`, `False` |
| `SOA Record` | String | SOA record content (DNS names only) | `ns1.example.com. admin.example.com.` |
| `Primary NS` | String | Primary nameserver from SOA | `ns1.example.com.` |
| `Admin Email` | String | Administrative contact from SOA | `admin.example.com.` |

### **Email Security Configuration**

| Column | Type | Description | Example Values |
|--------|------|-------------|----------------|
| `SPF Exists` | Boolean | SPF record found | `True`, `False` |
| `SPF Record` | String | Complete SPF policy | `"v=spf1 include:_spf.google.com ~all"` |
| `DKIM Exists` | Boolean | Any DKIM records found | `True`, `False` |
| `DKIM Records` | String | Semicolon-separated DKIM entries | `google:"v=DKIM1; k=rsa; p=...";k1:"v=DKIM1..."` |
| `DMARC Exists` | Boolean | DMARC record found | `True`, `False` |
| `DMARC Record` | String | Complete DMARC policy | `"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"` |

### **Subdomain Discovery**

| Column | Type | Description | Example Values |
|--------|------|-------------|----------------|
| `Discovered Subdomains` | String | Comma-separated subdomain list | `www.github.com,api.github.com,blog.github.com` |
| `CNAME Records` | String | Subdomain to CNAME mappings | `www.github.com:github.github.io.,api.github.com:api-lb.github.com.` |
| `Has Wildcard DNS` | Boolean | Wildcard DNS configuration detected | `True`, `False` |
| `Hosting Provider` | String | Detected hosting service | `AWS`, `Google Cloud`, `Cloudflare`, `null` |

Note: When wildcard DNS is present, the analyzer filters out subdomains that resolve solely due to wildcard records by comparing answers against a wildcard baseline (for A and CNAME). Subdomains are included when they have explicit CNAMEs or when their A answers differ from the wildcard baseline. Use `--include-wildcard-matches` to disable this filter, or `--filtered-subdomains-file` to export filtered items separately.

### **Web Security Analysis**

| Column | Type | Description | Example Values |
|--------|------|-------------|----------------|
| `HTTP Accessible` | Boolean | Domain responds to HTTP requests | `True`, `False` |
| `Redirects to HTTPS` | Boolean | HTTP traffic redirected to HTTPS | `True`, `False` |
| `Final URL` | String | Ultimate destination after redirects | `https://github.com/` |
| `Redirect Chain` | String | Arrow-separated redirect sequence | `http://github.com/ -> https://github.com/` |
| `HTTP Error` | String | Connection or HTTP errors | `Connection timeout`, `null` |

### **🆕 Subresource Integrity (SRI) Analysis**

| Column | Type | Description | Example Values |
|--------|------|-------------|----------------|
| `SRI Enabled` | Boolean | Any external resources use SRI | `True`, `False` |
| `Total External Resources` | Integer | Count of external JS/CSS files | `71`, `26`, `0` |
| `Resources With SRI` | Integer | Count with integrity attributes | `25`, `0` |
| `SRI Coverage %` | Float | Percentage of protected resources | `100.0`, `35.2`, `0.0` |
| `Missing SRI Count` | Integer | Unprotected external resources | `46`, `26`, `0` |
| `SRI Algorithms Used` | String | Comma-separated hash algorithms | `sha256,sha384`, `sha512`, `""` |
| `SRI Error` | String | SRI analysis errors | `SRI parsing error: ...`, `null` |

## Data Interpretation

### **Boolean Fields**
- `True`: Feature/condition is present
- `False`: Feature/condition is absent
- Empty cells in error conditions default to `False`

### **Numeric Fields**
- **Integers**: Exact counts (e.g., resource counts)
- **Floats**: Percentages with 1 decimal precision
- **Zero values**: No resources found or complete absence

### **String Fields**
- **Quoted strings**: Contain actual DNS/HTTP content
- **Comma-separated**: Multiple values in single field
- **Semicolon-separated**: Complex structured data (DKIM records)
- **Arrow-separated**: Sequential data (redirect chains)
- **Empty strings**: `""` or `null` for missing data

## SRI Analysis Interpretation

### **Coverage Assessment**
```
SRI Coverage % >= 90%  → Excellent security posture
SRI Coverage % 70-89%  → Good, minor gaps
SRI Coverage % 30-69%  → Moderate risk, improvement needed  
SRI Coverage % 1-29%   → Poor, significant risk
SRI Coverage % = 0%    → No protection, high risk
```

### **Resource Risk Evaluation**
```
Total External Resources = 0    → No external dependencies (safest)
Total External Resources 1-10   → Low complexity, manageable
Total External Resources 11-30  → Medium complexity, monitor closely
Total External Resources >30    → High complexity, SRI critical
```

### **Algorithm Security Assessment**
```
sha512 only     → Maximum security
sha384 only     → Recommended security  
sha256 only     → Minimum acceptable
Mixed algorithms → Inconsistent but acceptable
No algorithms   → No SRI protection
```

## Common Analysis Patterns

### **Secure Configuration Example**
```csv
Domain,SRI Enabled,Total External Resources,Resources With SRI,SRI Coverage %,SRI Algorithms Used
secure.example.com,True,8,8,100.0,"sha384,sha512"
```

### **Partial Implementation Example**
```csv  
Domain,SRI Enabled,Total External Resources,Resources With SRI,SRI Coverage %,Missing SRI Count
partial.example.com,True,15,7,46.7,8
```

### **High-Risk Configuration Example**
```csv
Domain,SRI Enabled,Total External Resources,Resources With SRI,SRI Coverage %,Missing SRI Count
risky.example.com,False,42,0,0.0,42
```

## Error Handling

### **Common Error Scenarios**
1. **DNS Resolution Failures**: SOA/email security fields show `False`
2. **HTTP Timeouts**: Web security fields show `False` with error message
3. **HTML Parsing Issues**: SRI fields show `0` with error in `SRI Error`
4. **Network Connectivity**: All fields populated with default values + error details

### **Error Field Population**
When analysis fails, the CSV row includes:
- All boolean fields: `False`
- All numeric fields: `0`
- All string fields: `""` (empty) or error message
- Ensures consistent 29-column output even with failures

## Data Usage Recommendations

### **Security Dashboards**
- Focus on `SRI Coverage %` for executive reporting
- Use `Missing SRI Count` for remediation prioritization
- Track `Total External Resources` for risk assessment

### **Compliance Reporting**
- `DMARC Exists` and `SPF Exists` for email security compliance
- `SRI Enabled` for modern security standard adoption
- `Redirects to HTTPS` for web security requirements

### **Risk Analysis**
- Combine high `Total External Resources` with low `SRI Coverage %`
- Identify domains with `Has Wildcard DNS = True` for DNS security review
- Monitor `HTTP Error` patterns for infrastructure issues

### **Historical Trending**
- Track `Timestamp` for change detection
- Compare `SRI Coverage %` over time for progress monitoring
- Analyze `SRI Algorithms Used` evolution for security improvements

## Integration with Security Tools

### **SIEM Integration**
- Import CSV data for security event correlation
- Use `Timestamp` for temporal analysis
- Alert on `SRI Coverage %` drops below thresholds

### **Risk Management Platforms**
- Map `SRI Coverage %` to risk scores
- Use `Hosting Provider` for vendor risk assessment
- Correlate `External Resources` with supply chain risk

### **Security Scorecard Alignment**
- `SRI Coverage %` directly supports SecurityScorecard SRI scoring
- Email security fields (SPF/DKIM/DMARC) align with email security scores
- `Redirects to HTTPS` supports web application security ratings
