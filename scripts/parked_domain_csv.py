import csv
import argparse

HEADER = [
    "Action",
    "Zone",
    "Record Name",
    "Record Type",
    "TTL",
    "Value",
    "Comments",
]

DEFAULT_DMARC_CNAME = "reject.dmarc.fabrikam.com."

RECORD_TEMPLATE = [
    ["REMOVE", "{domain}", "@", "MX", "", "10 custmx.cscdns.net.", "Remove existing MX record"],
    ["ADD", "{domain}", "@", "TXT", "3600", "v=spf1 -all", "SPF hard fail"],
    ["ADD", "{domain}", "@", "MX", "3600", "0 .", "Null MX (RFC 7505)"],
    ["ADD", "{domain}", "*._domainkey", "TXT", "3600", "v=DKIM1; p=", "DKIM wildcard with empty key"],
    ["ADD", "{domain}", "_dmarc", "CNAME", "3600", "{dmarc_target}", "DMARC reject policy via CNAME"],
]


def generate_records(domain: str, dmarc_target: str):
    records = [[f"--- {domain} ---", "", "", "", "", "", "Domain configuration"]]
    for template in RECORD_TEMPLATE:
        value = template[5].format(dmarc_target=dmarc_target)
        records.append([
            template[0],
            domain,
            template[2],
            template[3],
            template[4],
            value,
            template[6],
        ])
    return records


def main():
    parser = argparse.ArgumentParser(
        description="Generate CSV records to lock down parked or non-mailing domains"
    )
    parser.add_argument("domain_file", help="Text file containing domain names")
    parser.add_argument("output_csv", help="Path to write the output CSV")
    parser.add_argument(
        "--dmarc-cname",
        default=DEFAULT_DMARC_CNAME,
        help="DMARC CNAME target (default: %(default)s)",
    )

    args = parser.parse_args()

    domain_file = args.domain_file
    output_csv = args.output_csv
    dmarc_cname = args.dmarc_cname

    with open(domain_file, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(HEADER)
        for domain in domains:
            for row in generate_records(domain, dmarc_cname):
                writer.writerow(row)


if __name__ == "__main__":
    main()
