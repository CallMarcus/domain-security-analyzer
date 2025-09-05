# Subresource Integrity (SRI) Reference

## Overview

Subresource Integrity (SRI) is a W3C security feature that enables browsers to verify that files fetched from CDNs or external sources have not been tampered with. This is critical for preventing supply chain attacks where malicious code is injected into third-party resources.

## Why SRI Matters

### Security Benefits
- **Supply Chain Protection**: Prevents execution of tampered external JavaScript/CSS
- **Content Verification**: Ensures external resources match expected cryptographic hashes
- **Attack Mitigation**: Blocks execution if resource integrity validation fails
- **Zero-Trust Model**: Don't trust external resources without verification

### SecurityScorecard Scoring
SecurityScorecard now includes SRI implementation in their security scoring methodology, making this a crucial compliance requirement for organizations tracking their security posture.

## SRI Implementation

### Basic Syntax

```html
<!-- JavaScript with SRI -->
<script src="https://cdn.example.com/library.js" 
        integrity="sha384-abc123..."
        crossorigin="anonymous"></script>

<!-- CSS with SRI -->
<link rel="stylesheet" 
      href="https://cdn.example.com/styles.css"
      integrity="sha384-def456..."
      crossorigin="anonymous">
```

### Hash Algorithms
- **SHA-256**: Minimum recommended (`sha256-`)
- **SHA-384**: Better security (`sha384-`) - **Recommended**
- **SHA-512**: Maximum security (`sha512-`)

### Crossorigin Attribute
Required for cross-origin resources. Common values:
- `anonymous`: No credentials sent
- `use-credentials`: Send credentials if same-origin

## Domain Analyzer SRI Scanning

### What Gets Analyzed
The domain analyzer scans for:

1. **External JavaScript Files**
   ```html
   <script src="https://external-domain.com/script.js"></script>
   ```

2. **External CSS Stylesheets**
   ```html
   <link rel="stylesheet" href="https://cdn.example.com/style.css">
   ```

### SRI Metrics Captured

| Metric | Description | CSV Column |
|--------|-------------|------------|
| **SRI Enabled** | Boolean indicating any SRI usage | `SRI Enabled` |
| **Resource Count** | Total external resources found | `Total External Resources` |
| **Protected Count** | Resources with integrity attributes | `Resources With SRI` |
| **Coverage Percentage** | (Protected / Total) × 100 | `SRI Coverage %` |
| **Missing Protection** | Resources without SRI | `Missing SRI Count` |
| **Hash Algorithms** | Detected algorithms (sha256, sha384, sha512) | `SRI Algorithms Used` |
| **Parsing Errors** | Issues during analysis | `SRI Error` |

### Example Analysis Results

```csv
Domain,SRI Enabled,Total External Resources,Resources With SRI,SRI Coverage %
github.com,False,71,0,0.0
stackoverflow.com,False,26,0,0.0
bootstrap.com,True,4,4,100.0
```

## Best Practices

### Implementation Guidelines

1. **Start with Critical Resources**
   - Prioritize main framework files (jQuery, React, etc.)
   - Focus on authentication/payment related scripts

2. **Use Strong Hash Algorithms**
   - Prefer SHA-384 or SHA-512
   - Avoid SHA-256 for high-security applications

3. **Include Crossorigin Attribute**
   ```html
   <script src="https://cdn.example.com/lib.js"
           integrity="sha384-..."
           crossorigin="anonymous"></script>
   ```

4. **Monitor Resource Updates**
   - Hash values change when resources update
   - Implement monitoring for integrity failures

### Common Implementation Issues

1. **Missing Crossorigin**
   ```html
   <!-- ❌ Wrong: Missing crossorigin -->
   <script src="https://cdn.example.com/lib.js" 
           integrity="sha384-..."></script>
   
   <!-- ✅ Correct: Includes crossorigin -->
   <script src="https://cdn.example.com/lib.js" 
           integrity="sha384-..."
           crossorigin="anonymous"></script>
   ```

2. **Incorrect Hash Format**
   ```html
   <!-- ❌ Wrong: Invalid hash format -->
   <script src="..." integrity="abc123"></script>
   
   <!-- ✅ Correct: Proper algorithm prefix -->
   <script src="..." integrity="sha384-abc123..."></script>
   ```

3. **Same-Origin Resources**
   - SRI not required for same-domain resources
   - Focus on external CDN and third-party resources

## Generating SRI Hashes

### Command Line Tools

```bash
# Generate SHA-384 hash for a file
cat library.js | openssl dgst -sha384 -binary | openssl base64 -A

# Generate SHA-256 hash
curl -s https://cdn.example.com/lib.js | openssl dgst -sha256 -binary | openssl base64 -A
```

### Online Tools
- [SRI Hash Generator](https://www.srihash.org/)
- [Mozilla SRI Hash Generator](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)

### Automated Solutions
- **Webpack**: `webpack-subresource-integrity` plugin
- **Gulp**: `gulp-sri-hash` plugin  
- **Grunt**: `grunt-sri` plugin

## Security Scorecard Integration

### Risk Assessment Factors
- **High External Resource Usage**: Indicates greater attack surface
- **Zero SRI Coverage**: Maximum supply chain attack risk
- **Partial Implementation**: Inconsistent security posture
- **Algorithm Weakness**: Use of deprecated hash functions

### Compliance Scoring
- **100% Coverage**: Excellent security posture
- **75-99% Coverage**: Good, minor gaps to address
- **25-74% Coverage**: Moderate risk, significant improvement needed
- **0-24% Coverage**: High risk, immediate action required

### Remediation Priorities

1. **Critical Domains** (Customer-facing, financial)
   - Target 100% SRI coverage
   - Use SHA-384 or stronger

2. **Internal/Development Domains**
   - Target 75%+ coverage
   - Focus on authentication resources

3. **Parked/Marketing Domains**
   - Assess based on resource usage
   - May have lower priority

## Browser Compatibility

| Browser | SRI Support |
|---------|-------------|
| Chrome | 45+ ✅ |
| Firefox | 43+ ✅ |
| Safari | 11.1+ ✅ |
| Edge | 17+ ✅ |
| IE | Not Supported ❌ |

## Additional Resources

- [W3C SRI Specification](https://www.w3.org/TR/SRI/)
- [MDN SRI Documentation](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [SecurityScorecard Documentation](https://securityscorecard.readme.io/)