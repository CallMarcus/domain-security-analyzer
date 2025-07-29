# DKIM (DomainKeys Identified Mail) Reference Guide

## Overview

DKIM (DomainKeys Identified Mail) is an email authentication method that uses cryptographic signatures to verify that an email message was sent by an authorized mail server and hasn't been altered in transit. DKIM adds a digital signature to the email headers using public-key cryptography.

## How DKIM Works

1. **Signing**: Sending mail server signs outgoing emails with a private key
2. **Publishing**: Domain publishes public key in DNS as a TXT record
3. **Verification**: Receiving server retrieves public key and verifies signature

## DKIM DNS Record Structure

### Record Format

DKIM records are published at:
```
selector._domainkey.domain.com
```

### Basic Syntax

```
v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ...
```

## DKIM Record Tags

### Required Tags

- **`v=`**: Version (always "DKIM1")
- **`p=`**: Public key data (base64 encoded)

### Optional Tags

- **`k=`**: Key type (default: "rsa")
- **`h=`**: Acceptable hash algorithms (default: all)
- **`s=`**: Service type (default: "*")
- **`t=`**: Flags
- **`n=`**: Notes for administrators
- **`g=`**: Granularity of the key

## Valid DKIM Record Examples

### Standard RSA Key

```dns
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgdfgQIDAQAB"
```

### With Additional Parameters

```dns
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; t=s; n=This is our production key; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDfgdfgdfgdfgdfgdfgdfgdfgdfgdfgQIDAQAB"
```

### Revoked Key

```dns
selector._domainkey.example.com TXT "v=DKIM1; p="
```

### Split Long Keys

```dns
selector._domainkey.example.com TXT ( "v=DKIM1; k=rsa; "
    "p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890"
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567"
    "890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ..." )
```

## Key Sizes and Security

### Recommended Key Sizes

- **Minimum**: 1024 bits (being phased out)
- **Recommended**: 2048 bits
- **Maximum**: 4096 bits (may cause DNS issues)

### Example Key Generation

```bash
# Generate 2048-bit key pair
openssl genrsa -out private.key 2048
openssl rsa -in private.key -pubout -out public.key
```

## DKIM Selectors

### Purpose

Selectors allow multiple DKIM keys per domain:
- Key rotation
- Different keys for different systems
- Testing new keys

### Naming Conventions

```dns
# Date-based
202501._domainkey.example.com
20250115._domainkey.example.com

# Service-based
google._domainkey.example.com
mandrill._domainkey.example.com

# Environment-based
prod._domainkey.example.com
test._domainkey.example.com

# Generic
s1._domainkey.example.com
default._domainkey.example.com
k1._domainkey.example.com
```

## Best Practices

### 1. Use 2048-bit Keys

```dns
# GOOD: 2048-bit key
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."

# AVOID: 1024-bit key (too weak)
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC..."
```

### 2. Implement Key Rotation

```dns
# Current key
202501._domainkey.example.com TXT "v=DKIM1; k=rsa; p=CURRENT_KEY"

# New key (during transition)
202502._domainkey.example.com TXT "v=DKIM1; k=rsa; p=NEW_KEY"

# Old key (keep for verification of old emails)
202412._domainkey.example.com TXT "v=DKIM1; k=rsa; p=OLD_KEY"
```

### 3. Sign Important Headers

Configure your mail server to sign:
- From
- To
- Subject
- Date
- Message-ID
- Content-Type
- Reply-To (if present)

### 4. Use Descriptive Selectors

```dns
# GOOD: Meaningful selectors
google-2025._domainkey.example.com
marketing-prod._domainkey.example.com
transactional-01._domainkey.example.com

# POOR: Non-descriptive
x._domainkey.example.com
key._domainkey.example.com
dkim._domainkey.example.com
```

### 5. Monitor Key Usage

Track which keys are being used:
- Review DMARC reports
- Monitor mail logs
- Set up alerts for signing failures

## Common Pitfalls

### 1. DNS Record Formatting Issues

```dns
# WRONG: Missing quotes
selector._domainkey.example.com TXT v=DKIM1; k=rsa; p=MIGfMA...

# WRONG: Line breaks in key
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIGfMA
0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC"

# CORRECT: Proper quoting and no line breaks in key
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC..."
```

### 2. Key Size Problems

```dns
# TOO LARGE: 4096-bit keys may exceed DNS limits
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIICIQC..."

# Solution: Use 2048-bit keys
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MIIBIjA..."
```

### 3. Incorrect Selector Usage

```dns
# WRONG: Missing ._domainkey
selector.example.com TXT "v=DKIM1; k=rsa; p=..."

# WRONG: Wrong subdomain format
_domainkey.selector.example.com TXT "v=DKIM1; k=rsa; p=..."

# CORRECT: selector._domainkey.domain
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=..."
```

### 4. Private Key Exposure

```dns
# NEVER publish private keys!
# This is a PUBLIC key record - only publish the public key
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=PUBLIC_KEY_HERE"
```

### 5. Using Test Mode in Production

The `t=y` flag indicates that the DKIM record is in testing mode. Verifiers may ignore the DKIM signature if this flag is present, even if the signature is valid. This flag should not be used for production keys.

```dns
# WRONG: Production key in test mode
prod._domainkey.example.com TXT "v=DKIM1; t=y; p=..."

# CORRECT: Remove t=y for production
prod._domainkey.example.com TXT "v=DKIM1; p=..."
```

### 6. Forgetting Subdomain Keys

```dns
# Main domain key
selector._domainkey.example.com TXT "v=DKIM1; k=rsa; p=..."

# Don't forget subdomain keys if they send mail
selector._domainkey.mail.example.com TXT "v=DKIM1; k=rsa; p=..."
selector._domainkey.newsletter.example.com TXT "v=DKIM1; k=rsa; p=..."
```

## DKIM for Different Scenarios

### Third-Party Email Services

```dns
# Google Workspace
google._domainkey.example.com TXT "v=DKIM1; k=rsa; p=GOOGLE_PROVIDED_KEY"

# SendGrid
s1._domainkey.example.com CNAME s1.domainkey.u1234567.wl.sendgrid.net
s2._domainkey.example.com CNAME s2.domainkey.u1234567.wl.sendgrid.net

# Multiple providers
mandrill._domainkey.example.com TXT "v=DKIM1; k=rsa; p=MANDRILL_KEY"
ses._domainkey.example.com TXT "v=DKIM1; k=rsa; p=AWS_SES_KEY"
```

### Non-Sending Domains

```dns
# Wildcard to prevent unauthorized DKIM signing
*._domainkey.example.com TXT "v=DKIM1; p="
```

### Testing New Keys

```dns
# Production key
prod._domainkey.example.com TXT "v=DKIM1; k=rsa; p=PRODUCTION_KEY"

# Test key (with restricted flag)
test._domainkey.example.com TXT "v=DKIM1; k=rsa; t=y; p=TEST_KEY"
```

## Key Rotation Strategy

### Phase 1: Preparation

```dns
# Current active key
current._domainkey.example.com TXT "v=DKIM1; k=rsa; p=CURRENT_KEY"
```

### Phase 2: Introduction

```dns
# Keep current key
current._domainkey.example.com TXT "v=DKIM1; k=rsa; p=CURRENT_KEY"

# Add new key
new._domainkey.example.com TXT "v=DKIM1; k=rsa; p=NEW_KEY"
```

### Phase 3: Migration

- Start signing with new selector
- Monitor both keys
- Verify new key is working

### Phase 4: Deprecation

```dns
# Old key (keep for 30+ days for in-transit mail)
old._domainkey.example.com TXT "v=DKIM1; k=rsa; p=CURRENT_KEY"

# New key becomes current
current._domainkey.example.com TXT "v=DKIM1; k=rsa; p=NEW_KEY"
```

### Phase 5: Removal

```dns
# Remove or revoke old key
old._domainkey.example.com TXT "v=DKIM1; p="

# Only current key remains
current._domainkey.example.com TXT "v=DKIM1; k=rsa; p=NEW_KEY"
```

## Troubleshooting Guide

### DKIM Signature Failures

1. **Check DNS propagation**
   ```bash
   dig TXT selector._domainkey.example.com +short
   ```

2. **Verify key format**
   - No line breaks in public key
   - Proper base64 encoding
   - Correct record syntax

3. **Confirm selector matches**
   - Email header selector matches DNS record
   - No typos in selector name

### Body Hash Mismatches

- Check for content modification in transit
- Verify mail server isn't altering messages
- Look for security appliances modifying content

### DNS Query Failures

- Ensure record is published at correct location
- Check for DNS server issues
- Verify no DNSSEC problems

## DKIM Headers in Email

### Example DKIM-Signature Header

```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=example.com; s=selector;
    h=from:to:cc:subject:date:message-id:content-type;
    bh=rBTqc1nOyXBOoV9aGJPzGdRkpgUBZ8EwQVpQ8FwpA=;
    b=dQgQkP3JoF3lAClB3EoQQOx3TnuBFBhGp1TtlhGOEfQP7lkQ...
```

### Key Components

- **v=**: Version (always "1")
- **a=**: Algorithm (e.g., rsa-sha256)
- **c=**: Canonicalization (header/body)
- **d=**: Signing domain
- **s=**: Selector
- **h=**: Signed headers
- **bh=**: Body hash
- **b=**: Signature

## Testing and Validation

### Manual Testing

1. Send test email to a DKIM validator
2. Check email headers for DKIM-Signature
3. Verify Authentication-Results header

### DNS Verification

```bash
# Check DKIM record exists
dig TXT selector._domainkey.example.com

# Verify record format
echo "record_content" | grep "v=DKIM1"
```

### Common Validation Results

```
# PASS
Authentication-Results: mx.google.com;
    dkim=pass header.i=@example.com header.s=selector

# FAIL - Key not found
Authentication-Results: mx.google.com;
    dkim=fail (key not found) header.i=@example.com

# FAIL - Signature verification failed
Authentication-Results: mx.google.com;
    dkim=fail (signature verification failed) header.i=@example.com
```

## Summary

DKIM is a crucial email authentication technology that requires careful implementation and maintenance:

1. Use 2048-bit RSA keys for optimal security
2. Implement proper key rotation procedures
3. Use meaningful selector names
4. Monitor DKIM signing and validation
5. Keep DNS records properly formatted
6. Coordinate with DMARC for alignment
7. Test thoroughly before and after changes

Combined with SPF and DMARC, DKIM forms a comprehensive email authentication strategy that protects against forgery and phishing.