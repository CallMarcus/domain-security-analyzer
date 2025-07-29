# SPF (Sender Policy Framework) Reference Guide

## Overview

SPF (Sender Policy Framework) is an email authentication protocol that allows domain owners to specify which mail servers are authorized to send email on behalf of their domain. SPF records are published as DNS TXT records.

## SPF Record Structure

### Basic Syntax

```
v=spf1 [mechanisms] [modifiers]
```

### Components

- **Version**: Always starts with `v=spf1`
- **Mechanisms**: Define which hosts are authorized to send mail
- **Qualifiers**: Prefix mechanisms to specify the result
- **Modifiers**: Provide additional information

## Valid SPF Mechanisms

### IP-Based Mechanisms

```dns
# IPv4 address
v=spf1 ip4:192.168.1.1 ~all

# IPv4 subnet
v=spf1 ip4:192.168.0.0/16 ~all

# IPv6 address
v=spf1 ip6:2001:db8::1 ~all

# IPv6 subnet
v=spf1 ip6:2001:db8::/32 ~all
```

### Domain-Based Mechanisms

```dns
# A record of current domain
v=spf1 a ~all

# A record of specified domain
v=spf1 a:mail.example.com ~all

# MX records of current domain
v=spf1 mx ~all

# MX records of specified domain
v=spf1 mx:example.com ~all

# Include another domain's SPF record
v=spf1 include:_spf.google.com ~all

# Check if domain exists
v=spf1 exists:%{i}.whitelist.example.com ~all
```

### Special Mechanisms

```dns
# Allow all (NOT RECOMMENDED)
v=spf1 +all

# The current domain itself
v=spf1 ptr ~all  # DEPRECATED - DO NOT USE
```

## Qualifiers

Each mechanism can be prefixed with a qualifier:

- **`+`** (Pass): Allow the host (default if omitted)
- **`-`** (Fail): Reject the host
- **`~`** (SoftFail): Mark as suspicious but don't reject
- **`?`** (Neutral): No policy statement

### Examples

```dns
v=spf1 +ip4:192.168.1.0/24 -ip4:192.168.1.99 ~all
```

## Modifiers

### redirect

Redirects SPF checks to another domain:

```dns
v=spf1 redirect=_spf.example.com
```

### exp

Provides explanation for failures:

```dns
v=spf1 mx -all exp=explain.example.com
```

## Best Practices

### 1. Start with Monitoring

Begin with a soft fail to monitor before enforcing:

```dns
# Initial deployment
v=spf1 include:_spf.google.com include:mail.protection.outlook.com ~all

# After validation
v=spf1 include:_spf.google.com include:mail.protection.outlook.com -all
```

### 2. Keep It Simple

Minimize DNS lookups and complexity:

```dns
# GOOD: Direct IP specification
v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 -all

# BAD: Too many includes
v=spf1 include:provider1.com include:provider2.com include:provider3.com include:provider4.com include:provider5.com -all
```

### 3. Use Specific IP Ranges

Be as specific as possible with IP ranges:

```dns
# GOOD: Specific subnet
v=spf1 ip4:192.0.2.0/28 -all

# BAD: Overly broad
v=spf1 ip4:192.0.0.0/8 -all
```

### 4. Maintain Include Chains

When using includes, understand the chain:

```dns
# Main domain
example.com:     v=spf1 include:_spf.example.com -all

# Included record
_spf.example.com: v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 ~all
```

### 5. Document Your SPF

Add comments in DNS management system:

```dns
# Production mail servers (datacenter 1 and 2) + Google Workspace
v=spf1 ip4:192.0.2.0/24 ip4:198.51.100.0/24 include:_spf.google.com -all
```

## Common Pitfalls

### 1. DNS Lookup Limit (10 Lookups)

SPF has a hard limit of 10 DNS lookups. Mechanisms that count:

- `include:`
- `a`
- `mx`
- `ptr` (deprecated)
- `exists:`
- `redirect=`

```dns
# BAD: May exceed lookup limit
v=spf1 include:provider1.com include:provider2.com mx a -all

# GOOD: Use IP addresses when possible
v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all
```

### 2. Void Lookup Limit (2 Lookups)

In addition to the 10-lookup limit, there is a separate limit of 2 "void" lookups. A void lookup occurs when a DNS query for a mechanism (like `include:` or `exists:`) returns no records (an NXDOMAIN or NODATA response). Exceeding this limit will cause a PermError, invalidating the SPF check. This often happens with misspelled domains or when a third-party service is removed without updating the SPF record.

### 3. Multiple SPF Records

Only ONE SPF record per domain is allowed:

```dns
# WRONG: Two separate TXT records
example.com TXT "v=spf1 include:_spf.google.com ~all"
example.com TXT "v=spf1 include:mail.protection.outlook.com ~all"

# CORRECT: Combined into one record
example.com TXT "v=spf1 include:_spf.google.com include:mail.protection.outlook.com ~all"
```

### 4. Syntax Errors

Common syntax mistakes:

```dns
# WRONG: Missing version
"ip4:192.0.2.1 -all"

# WRONG: Wrong version
"v=spf2 ip4:192.0.2.1 -all"

# WRONG: Invalid mechanism
"v=spf1 ipv4:192.0.2.1 -all"

# CORRECT
"v=spf1 ip4:192.0.2.1 -all"
```

### 5. Trailing Dots in Includes

Be careful with DNS notation:

```dns
# WRONG: Trailing dot in include
v=spf1 include:_spf.google.com. -all

# CORRECT: No trailing dot
v=spf1 include:_spf.google.com -all
```

### 6. Circular References

Avoid circular include references:

```dns
# Domain A includes Domain B
domainA.com: v=spf1 include:domainB.com -all

# Domain B includes Domain A (CIRCULAR!)
domainB.com: v=spf1 include:domainA.com -all
```
**Note**: Circular references can lead to infinite loops and SPF validation failures.

## SPF for Different Scenarios

### Non-Sending Domain

```dns
# Domain that never sends email
v=spf1 -all
```

### Single Mail Server

```dns
# One dedicated mail server
v=spf1 ip4:192.0.2.1 -all
```

### Multiple Providers

```dns
# Google Workspace + Marketing platform
v=spf1 include:_spf.google.com include:spf.mandrillapp.com -all
```

### With Subdomains

```dns
# Include parent domain's mail servers
v=spf1 include:example.com -all
```

## Testing and Validation

### 1. Check Record Syntax

Ensure proper formatting:

```bash
$ dig +short TXT example.com | grep spf1
"v=spf1 include:_spf.google.com -all"
```

### 2. Count DNS Lookups

Manually trace through includes to count lookups.

### 3. Test with Online Tools

Use SPF validators to check:
- Syntax validity
- DNS lookup count
- Include chain resolution

### 4. Monitor Email Headers

Check SPF results in email headers:

```
Received-SPF: pass (google.com: domain of sender@example.com designates 192.0.2.1 as permitted sender)
```

## SPF Record Length Limitations

### TXT Record Limits

- Single string: 255 characters max
- Multiple strings: Can be concatenated
- Total: Varies by DNS provider (typically 4096 characters)

### Handling Long Records

```dns
# Split into multiple strings (automatically concatenated)
example.com TXT "v=spf1 "
                "ip4:192.0.2.0/24 "
                "ip4:198.51.100.0/24 "
                "include:_spf.google.com "
                "-all"
```

## Migration Strategies

### Gradual Rollout

1. **Phase 1**: Deploy with `?all` (neutral)
   ```dns
   v=spf1 include:_spf.google.com ?all
   ```

2. **Phase 2**: Move to `~all` (soft fail)
   ```dns
   v=spf1 include:_spf.google.com ~all
   ```

3. **Phase 3**: Enforce with `-all` (hard fail)
   ```dns
   v=spf1 include:_spf.google.com -all
   ```

### Adding New Services

```dns
# Before adding new service
v=spf1 include:_spf.google.com -all

# Temporarily soften while testing
v=spf1 include:_spf.google.com ~all

# Add new service
v=spf1 include:_spf.google.com include:amazonses.com ~all

# Re-harden after validation
v=spf1 include:_spf.google.com include:amazonses.com -all
```

## Troubleshooting Guide

### SPF Failures Despite Correct Configuration

1. **Check DNS propagation**: Records may take time to update
2. **Verify IP addresses**: Ensure sending IPs match SPF record
3. **Review include chains**: Included records may have changed
4. **Check for typos**: Even small errors invalidate the record

### Intermittent Failures

- Monitor if provider IPs change
- Check if includes are hitting lookup limits
- Verify no duplicate or conflicting records

### Performance Issues

- Reduce DNS lookups by using IP addresses
- Consolidate multiple includes where possible
- Consider dedicated SPF subdomains for organization

## Summary

SPF is a critical email authentication mechanism that requires careful planning and maintenance. Key takeaways:

1. Always start with `v=spf1`
2. Keep under 10 DNS lookups
3. Use specific IP ranges when possible
4. Test thoroughly before enforcing with `-all`
5. Monitor and maintain records as infrastructure changes
6. Combine with DKIM and DMARC for complete email authentication