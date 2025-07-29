# Complete DMARC Implementation Guide for Parked Domains

## Overview

This guide provides a comprehensive approach to implementing DMARC across
multiple domains, including parked domains that don't send mail, using a
centralized CNAME-based configuration.

## Architecture

The solution uses a centralized approach where:

- Main domain hosts three policy-specific DMARC records
- Parked domains use CNAME records to point to appropriate policies
- Non-mailing domains are properly configured to reject all mail

## Main Domain Configuration

### Step 1: Create Policy-Specific DMARC Records

On your main domain, create three distinct DMARC policy records:

```dns
# Policy: None (monitoring only)
dmarc-none.maindomain.com        IN  TXT  "v=DMARC1; p=none;
                                          rua=mailto:reports@maindomain.com;"

# Policy: Quarantine (suspicious emails to spam)
dmarc-quarantine.maindomain.com  IN  TXT  "v=DMARC1; p=quarantine;
                                          rua=mailto:reports@maindomain.com;"

# Policy: Reject (block suspicious emails)
dmarc-reject.maindomain.com      IN  TXT  "v=DMARC1; p=reject;
                                          rua=mailto:reports@maindomain.com;"
```

## Parked Domain Configuration

### Step 2: Configure Parked Domains with CNAME Records

For each parked domain, create a CNAME record pointing to the appropriate
policy:

```dns
# Monitoring phase domains
_dmarc.parkeddomain1.com    IN  CNAME  dmarc-none.maindomain.com

# Quarantine phase domains
_dmarc.parkeddomain2.com    IN  CNAME  dmarc-quarantine.maindomain.com

# Reject phase domains
_dmarc.parkeddomain3.com    IN  CNAME  dmarc-reject.maindomain.com
```

### Step 3: Configure Non-Mailing Domain Records

For domains that don't send mail, implement the complete email security
stack to prevent abuse and spoofing:

#### SPF Configuration

Configure SPF to hard fail all mail attempts:

```dns
domain.com  IN  TXT  "v=spf1 -all"
```

**What this does**: The `-all` mechanism creates a hard fail for any mail
claiming to be from this domain, since no sending sources are authorized.

#### DKIM Configuration

Create a wildcard DKIM record to indicate no DKIM signing:

```dns
*._domainkey.domain.com  IN  TXT  "v=DKIM1; p="
```

**What this does**: The empty `p=` parameter tells receiving mail servers
that no public key is available for any DKIM selector, effectively
disabling DKIM validation.

#### MX Record Configuration

Use the null MX record (RFC 7505 compliant - recommended):

```dns
domain.com  IN  MX  0  .
```

**What this does**: The dot (.) indicates a null MX record, explicitly
stating the domain doesn't accept mail according to RFC 7505.

#### DMARC Configuration

Point to the reject policy for maximum protection:

```dns
_dmarc.domain.com  IN  CNAME  dmarc-reject.maindomain.com
```

**Complete Non-Mailing Domain Example**:

```dns
# Complete setup for a domain that doesn't send mail
parkeddomain.com                    IN  TXT  "v=spf1 -all"
parkeddomain.com                    IN  MX   0   .
*._domainkey.parkeddomain.com      IN  TXT  "v=DKIM1; p="
_dmarc.parkeddomain.com            IN  CNAME dmarc-reject.maindomain.com
```

## Alternative MX Record Options

If null MX records aren't supported by your DNS provider:

### Option 2: Point to Non-Existent Host

```dns
domain.com  IN  MX  10  nowhere.invalid
```

**Benefits**: Uses `.invalid` TLD which is reserved and will never exist
**Drawbacks**: May cause sending servers to retry delivery attempts

### Option 3: Point to Localhost

```dns
domain.com  IN  MX  10  localhost
```

**Benefits**: Mail is immediately rejected at delivery attempt
**Drawbacks**: Generates immediate bounce messages to senders

### Option 4: Point to Blackhole Service

```dns
domain.com  IN  MX  10  blackhole.example.com
```

**Benefits**: Silently discards mail without bounces
**Drawbacks**: Requires maintaining a blackhole mail server

**Recommendation**: Use the null MX record (Option 1) as it's the most
standards-compliant and efficient approach.

## Implementation Phases

### Phase 1: Monitoring

Start all domains with the monitoring policy to collect data:

```dns
_dmarc.domain.com  IN  CNAME  dmarc-none.maindomain.com
```

### Phase 2: Quarantine

Move domains to quarantine after analyzing reports:

```dns
_dmarc.domain.com  IN  CNAME  dmarc-quarantine.maindomain.com
```

### Phase 3: Reject

Final implementation with full protection:

```dns
_dmarc.domain.com  IN  CNAME  dmarc-reject.maindomain.com
```

## DNS Change Management Template

Use this CSV template for submitting DNS changes:

```csv
RequestID,Action,Domain,RecordType,Host,PointsTo,TTL,Priority,Content,
Notes,RequestDate,RequestedBy,ApprovalStatus,ImplementationDate,
VerificationStatus,ProjectPhase

# MAIN DOMAIN POLICY RECORDS (PHASE 1)
DMARC-001,ADD,maindomain.com,TXT,dmarc-none,,,,
"v=DMARC1; p=none; rua=mailto:reports@maindomain.com;",
"Create monitoring policy record",2025-06-13,Admin,Pending,,,1
DMARC-002,ADD,maindomain.com,TXT,dmarc-quarantine,,,,
"v=DMARC1; p=quarantine; rua=mailto:reports@maindomain.com;",
"Create quarantine policy record",2025-06-13,Admin,Pending,,,1
DMARC-003,ADD,maindomain.com,TXT,dmarc-reject,,,,
"v=DMARC1; p=reject; rua=mailto:reports@maindomain.com;",
"Create reject policy record",2025-06-13,Admin,Pending,,,1

# NON-MAILING DOMAIN SETUP (PHASE 2)
DMARC-004,ADD,parkeddomain1.com,TXT,,"v=spf1 -all",3600,,,
"SPF hard fail for non-mailing domain",2025-06-13,Admin,Pending,,,2
DMARC-005,ADD,parkeddomain1.com,MX,,.,3600,0,,
"Null MX record for non-mailing domain",2025-06-13,Admin,Pending,,,2
DMARC-006,ADD,parkeddomain1.com,TXT,*._domainkey,,"v=DKIM1; p=",3600,,,
"DKIM wildcard empty key",2025-06-13,Admin,Pending,,,2
DMARC-007,ADD,parkeddomain1.com,CNAME,_dmarc,dmarc-reject.maindomain.com,
3600,,,"DMARC reject policy for non-mailing domain",
2025-06-13,Admin,Pending,,,2

# POLICY PROGRESSION EXAMPLE (PHASE 3)
DMARC-008,REMOVE,parkeddomain2.com,CNAME,_dmarc,
dmarc-none.maindomain.com,3600,,,
"Remove monitoring policy",2025-06-13,Admin,Pending,,,3
DMARC-009,ADD,parkeddomain2.com,CNAME,_dmarc,
dmarc-quarantine.maindomain.com,3600,,,
"Upgrade to quarantine policy",2025-06-13,Admin,Pending,,,3
```

## Benefits of This Approach

**Centralized Management**: All DMARC policies managed from one domain

**Easy Policy Changes**: Update domain policies by changing CNAME targets

**Scalable**: Add new domains by simply creating CNAME records

**Compliance**: Proper configuration for non-mailing domains

**Monitoring**: Centralized DMARC reports for all domains

## Verification Steps

1. **DNS Propagation**: Verify all records are properly propagated
2. **DMARC Reports**: Monitor incoming reports for policy effectiveness
3. **Email Testing**: Test that non-mailing domains properly reject mail
4. **CNAME Resolution**: Confirm CNAME records resolve to correct policy records

## Important Considerations

- Not all DNS providers support CNAME records at domain apex
- Some email receivers may not follow CNAME records for DMARC
- Test thoroughly in monitoring phase before enforcing policies
- Keep TTL values reasonable (3600 seconds recommended)
- Monitor DMARC reports continuously after implementation

## Troubleshooting

**CNAME Not Resolving**: Check DNS provider CNAME support and propagation

**Reports Not Received**: Verify RUA email address and report processing

**False Positives**: Review SPF and DKIM alignment in DMARC reports

**Policy Not Enforced**: Confirm receiving mail servers support DMARC CNAME resolution
