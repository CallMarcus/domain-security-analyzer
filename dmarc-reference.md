# DMARC (Domain-based Message Authentication, Reporting, and Conformance) Reference Guide

## Overview

DMARC (Domain-based Message Authentication, Reporting, and Conformance) is an email authentication protocol that builds on SPF and DKIM. It allows domain owners to specify how receiving mail servers should handle messages that fail authentication checks and provides reporting mechanisms for monitoring email authentication.

## How DMARC Works

1. **Authentication**: Checks SPF and DKIM results
2. **Alignment**: Verifies domain alignment
3. **Policy Application**: Applies sender's specified policy
4. **Reporting**: Sends aggregate and forensic reports

## DMARC Record Structure

### DNS Location

DMARC records are published as TXT records at:
```
_dmarc.domain.com
```

### Basic Syntax

```
v=DMARC1; p=none; rua=mailto:dmarc@example.com
```

## DMARC Tags

### Required Tags

- **`v=`**: Version (always "DMARC1")
- **`p=`**: Policy for main domain (none, quarantine, reject)

### Optional Tags

- **`rua=`**: Aggregate reports URI
- **`ruf=`**: Forensic reports URI
- **`sp=`**: Subdomain policy
- **`pct=`**: Percentage of messages to apply policy
- **`adkim=`**: DKIM alignment mode (r=relaxed, s=strict)
- **`aspf=`**: SPF alignment mode (r=relaxed, s=strict)
- **`fo=`**: Forensic report options
- **`rf=`**: Report format
- **`ri=`**: Report interval (seconds)

## Valid DMARC Record Examples

### Monitoring Mode

```dns
_dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
```

### Quarantine Policy

```dns
_dmarc.example.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com; pct=50"
```

### Reject Policy

```dns
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com"
```

### Full Configuration

```dns
_dmarc.example.com TXT "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; adkim=r; aspf=r; fo=1; rf=afrf; ri=86400"
```

## Policy Options

### Main Domain Policy (p=)

- **`none`**: No action, monitoring only
- **`quarantine`**: Treat as suspicious (usually spam folder)
- **`reject`**: Reject the message

### Subdomain Policy (sp=)

Same options as main domain policy. If not specified, inherits from `p=`.

### Policy Percentage (pct=)

```dns
# Apply policy to 25% of failing messages
v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@example.com

# Apply to all messages (default if omitted)
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com
```

## Alignment Options

### SPF Alignment (aspf=)

- **`r`** (relaxed): Subdomains can align
- **`s`** (strict): Exact domain match required

```dns
# Relaxed: mail from subdomain.example.com aligns with example.com
v=DMARC1; p=reject; aspf=r

# Strict: only mail from example.com aligns with example.com
v=DMARC1; p=reject; aspf=s
```

### DKIM Alignment (adkim=)

- **`r`** (relaxed): Subdomains can align
- **`s`** (strict): Exact domain match required

```dns
# Relaxed: DKIM d=subdomain.example.com aligns with From: example.com
v=DMARC1; p=reject; adkim=r

# Strict: DKIM d= must exactly match From: domain
v=DMARC1; p=reject; adkim=s
```

## Reporting Configuration

### Aggregate Reports (rua=)

Daily summaries of authentication results:

```dns
# Single recipient
v=DMARC1; p=none; rua=mailto:dmarc@example.com

# Multiple recipients
v=DMARC1; p=none; rua=mailto:dmarc@example.com,mailto:reports@monitoring.com

# With size limit (10MB)
v=DMARC1; p=none; rua=mailto:dmarc@example.com!10m
```

### Forensic Reports (ruf=)

Detailed reports for individual failures:

```dns
# Basic forensic reporting
v=DMARC1; p=none; ruf=mailto:forensics@example.com

# Multiple recipients
v=DMARC1; p=none; ruf=mailto:forensics@example.com,mailto:security@example.com
```

### Report Options (fo=)

Controls when forensic reports are sent:

- **`0`**: DKIM and SPF fail (default)
- **`1`**: DKIM or SPF fail
- **`d`**: DKIM fail
- **`s`**: SPF fail

```dns
# Report any authentication failure
v=DMARC1; p=none; ruf=mailto:forensics@example.com; fo=1
```

## Best Practices

### 1. Gradual Deployment

```dns
# Phase 1: Monitor only (1-4 weeks)
_dmarc.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

# Phase 2: Quarantine subset (2-4 weeks)
_dmarc.example.com TXT "v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@example.com"

# Phase 3: Quarantine all (2-4 weeks)
_dmarc.example.com TXT "v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@example.com"

# Phase 4: Reject subset (2-4 weeks)
_dmarc.example.com TXT "v=DMARC1; p=reject; pct=25; rua=mailto:dmarc@example.com"

# Phase 5: Full enforcement
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

### 2. Separate Report Addresses

```dns
# Use dedicated addresses for different report types
v=DMARC1; p=reject; 
  rua=mailto:dmarc-aggregate@example.com; 
  ruf=mailto:dmarc-forensic@example.com
```

### 3. External Report Processing

```dns
# Send reports to third-party processor
v=DMARC1; p=reject; 
  rua=mailto:12345@dmarc.service.com,mailto:dmarc@example.com
```

### 4. Subdomain Considerations

```dns
# Different policy for subdomains
v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com

# Inherit main domain policy (default)
v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

### 5. Monitor Before Enforcing

Always start with `p=none` and analyze reports before moving to enforcement policies.

## Common Pitfalls

### 1. Multiple DMARC Records

```dns
# WRONG: Two DMARC records
_dmarc.example.com TXT "v=DMARC1; p=none"
_dmarc.example.com TXT "v=DMARC1; p=reject"

# CORRECT: Single record
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

### 2. Invalid Email Addresses

```dns
# WRONG: Missing mailto:
v=DMARC1; p=none; rua=dmarc@example.com

# WRONG: Invalid syntax
v=DMARC1; p=none; rua=<dmarc@example.com>

# CORRECT: Proper mailto: URI
v=DMARC1; p=none; rua=mailto:dmarc@example.com
```

### 3. Subdomain DMARC Records

```dns
# Main domain DMARC
_dmarc.example.com TXT "v=DMARC1; p=reject; sp=none"

# Subdomain can override with its own policy
_dmarc.subdomain.example.com TXT "v=DMARC1; p=quarantine"
```

### 4. Report URI Authorization

When sending reports to external domains:

```dns
# Receiving domain must authorize
example.com._report._dmarc.reportprocessor.com TXT "v=DMARC1"
```

### 5. Percentage Confusion

```dns
# pct only applies to the policy action, not monitoring
# This still monitors 100% but only quarantines 50%
v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com
```

## DMARC for Different Scenarios

### Domains That Send Email

```dns
# Standard configuration
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; fo=1"
```

### Non-Sending Domains

```dns
# Immediate reject policy for parked domains
_dmarc.parkeddomain.com TXT "v=DMARC1; p=reject; rua=mailto:dmarc@maindomain.com"
```

### Mixed Subdomain Usage

```dns
# Main domain sends email, subdomains don't
_dmarc.example.com TXT "v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com"
```

### Testing Environment

```dns
# Separate policy for test subdomain
_dmarc.test.example.com TXT "v=DMARC1; p=none; rua=mailto:dmarc-test@example.com"
```

## Understanding DMARC Reports

### Aggregate Report Structure

```xml
<feedback>
  <report_metadata>
    <org_name>Google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <date_range>
      <begin>1234567890</begin>
      <end>1234654289</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>reject</p>
    <sp>reject</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
  </record>
</feedback>
```

### Key Report Elements

- **source_ip**: Sending server IP
- **count**: Number of messages
- **disposition**: Action taken (none/quarantine/reject)
- **dkim/spf**: Authentication results

## Troubleshooting Guide

### No Reports Received

1. **Check DNS propagation**
   ```bash
   dig TXT _dmarc.example.com +short
   ```

2. **Verify email addresses**
   - Ensure mailboxes exist
   - Check spam folders
   - Verify no size limits

3. **Confirm report authorization**
   - External processors may need authorization records

### Policy Not Applied

1. **Check record syntax**
   - Proper tag format
   - Valid policy values
   - No typos

2. **Verify one record exists**
   - No duplicate DMARC records
   - Check all nameservers

3. **Review alignment settings**
   - May be too strict
   - Check SPF/DKIM configuration

### High Failure Rates

1. **Identify legitimate sources**
   - Review source IPs in reports
   - Add missing sources to SPF
   - Configure DKIM for all senders

2. **Check forwarding**
   - Forwarded mail often fails
   - Consider relaxed alignment

3. **Monitor third-party senders**
   - Marketing platforms
   - CRM systems
   - Support ticketing systems

## Advanced Configurations

### Report Size Management

```dns
# Limit report size to 10MB
v=DMARC1; p=reject; rua=mailto:dmarc@example.com!10m

# Multiple limits
v=DMARC1; p=reject; rua=mailto:dmarc@example.com!10m,mailto:backup@example.com!50m
```

### Conditional Policies

```dns
# Gradual rollout with monitoring
v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; fo=1
```

### Cross-Domain Reporting

Authorize external report destinations:

```dns
# On example.com (sender)
_dmarc.example.com TXT "v=DMARC1; p=reject; rua=mailto:reports@processor.com"

# On processor.com (receiver)
example.com._report._dmarc.processor.com TXT "v=DMARC1"
```

## DMARC Deployment Checklist

### Pre-Deployment

- [ ] SPF record configured and tested
- [ ] DKIM signing enabled and verified
- [ ] Report processing system ready
- [ ] Identified all legitimate email sources
- [ ] Created dedicated report mailboxes

### Phase 1: Monitor

- [ ] Deploy with p=none
- [ ] Collect reports for 1-4 weeks
- [ ] Identify all legitimate senders
- [ ] Fix SPF/DKIM issues

### Phase 2: Quarantine

- [ ] Update to p=quarantine
- [ ] Start with pct=25
- [ ] Monitor for false positives
- [ ] Gradually increase percentage

### Phase 3: Reject

- [ ] Update to p=reject
- [ ] Consider starting with pct=25
- [ ] Monitor business impact
- [ ] Move to pct=100

### Post-Deployment

- [ ] Regular report analysis
- [ ] Update for new email sources
- [ ] Monitor authentication failures
- [ ] Maintain SPF and DKIM

## Summary

DMARC provides crucial email authentication enforcement and visibility:

1. Start with monitoring (p=none) to understand email flows
2. Gradually move to enforcement through quarantine and reject
3. Use percentage rollouts to minimize risk
4. Configure comprehensive reporting for visibility
5. Maintain alignment with SPF and DKIM configurations
6. Regular monitoring and updates are essential
7. Consider subdomain policies separately

Combined with properly configured SPF and DKIM, DMARC forms a complete email authentication framework that significantly reduces email spoofing and phishing risks.