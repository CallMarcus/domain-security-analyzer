# CSC Global DNS Template - DMARC Project Sample Records

## Sample Records Summary

Template with comprehensive examples of all DNS record types for the DMARC projects:

### Record Type Breakdown

- **TXT Records**: 7 records (SPF, DKIM, DMARC policies)
- **CNAME Records**: 7 records (DMARC policy pointers, domain upgrades)
- **MX Records**: 3 records (null MX, alternative non-mailing configurations)

## Sample Records Included

### 1. Main Domain Policy Records (Phase 1)

```dns
maindomain.com | TXT | dmarc-none       | v=DMARC1; p=none;
                                            rua=mailto:reports@maindomain.com;
maindomain.com | TXT | dmarc-quarantine | v=DMARC1; p=quarantine;
                                            rua=mailto:reports@maindomain.com;
maindomain.com | TXT | dmarc-reject     | v=DMARC1; p=reject;
                                            rua=mailto:reports@maindomain.com;
```

### 2. Complete Non-Mailing Domain Setup (Phase 2)

```dns
parkeddomain1.com | TXT   | @              | v=spf1 -all                     | SPF hard fail
parkeddomain1.com | MX    | @              | .                               | Null MX (RFC 7505)
parkeddomain1.com | TXT   | *._domainkey   | v=DKIM1; p=  | DKIM wildcard disable
parkeddomain1.com | CNAME | _dmarc         | dmarc-reject.maindomain.com
                                            | DMARC reject policy
```

### 3. Parked Domain CNAME Records (Phase 2)

```dns
parkeddomain2.com | CNAME | _dmarc | dmarc-none.maindomain.com       | Monitoring phase
parkeddomain3.com | CNAME | _dmarc | dmarc-quarantine.maindomain.com | Quarantine phase
parkeddomain4.com | CNAME | _dmarc | dmarc-reject.maindomain.com     | Reject phase
```

### 4. Alternative MX Configurations

```dns
example-invalid.com   | MX | @ | nowhere.invalid | Alternative non-mailing MX
example-localhost.com | MX | @ | localhost       | Localhost bounce MX
```

### 5. Policy Change Example (Phase 3)

```dns
upgrade-domain.com | CNAME | _dmarc | dmarc-none.maindomain.com       | Delete old policy
upgrade-domain.com | CNAME | _dmarc | dmarc-quarantine.maindomain.com | Add new policy
```

### 6. Active Domain Configuration

```dns
activedomain.com | TXT   | @            | v=spf1 include:_spf.google.com ~all
activedomain.com | TXT   | selector1._domainkey | v=DKIM1; k=rsa; p=MIGfMA0GC...
activedomain.com | CNAME | _dmarc              | dmarc-quarantine.maindomain.com
```

## CSC Global Template Column Structure

| Column | Field              | Description                                     |
|--------|--------------------|-------------------------------------------------|
| A      | Domain Name        | The domain where the DNS record will be created |
| B      | TYPE               | DNS record type (TXT, CNAME, MX, etc.)          |
| C      | Key                | The host/subdomain part of the record           |
| D      | Value              | The record content/target                       |
| E      | Priority/Flag(CAA) | Priority value for MX records                   |
| F      | Weight/Tag(CAA)    | Weight for SRV records                          |
| G      | Port               | Port for SRV records                            |
| H      | TTL                | Time-to-live in seconds                         |
| I      | Action             | Add, Delete, or Change TTL                      |

## Key Implementation Notes

### SPF Records for Non-Mailing Domains

- Use `v=spf1 -all` for hard fail on all mail
- Apply to the root domain (`@` key)

### DKIM Wildcard Disable

- Use `*._domainkey` as the key
- Set value to `v=DKIM1; p=` (empty public key)
- Disables DKIM for all selectors

### Null MX Records

- Use `.` (dot) as the value
- Set priority to `0`
- Most RFC-compliant way to indicate no mail acceptance

### DMARC CNAME Strategy

- Point `_dmarc` subdomain to centralized policy records
- Enables easy policy management across multiple domains
- Allows phased rollout from monitoring to enforcement

### Policy Progression Example

The template shows how to change a domain's DMARC policy:

1. Delete the old CNAME record
2. Add the new CNAME record pointing to the desired policy

This ensures clean transitions between DMARC policies while maintaining
audit trails in your DNS change management system.
