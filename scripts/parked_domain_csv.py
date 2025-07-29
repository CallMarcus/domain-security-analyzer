import csv
import sys

HEADER = [
    "Action",
    "Zone",
    "Record Name",
    "Record Type",
    "TTL",
    "Value",
    "Comments",
]

RECORD_TEMPLATE = [
    ["REMOVE", "{domain}", "@", "MX", "", "10 custmx.cscdns.net.", "Remove existing MX record"],
    ["ADD", "{domain}", "@", "TXT", "3600", "v=spf1 -all", "SPF hard fail"],
    ["ADD", "{domain}", "@", "MX", "3600", "0 .", "Null MX (RFC 7505)"],
    ["ADD", "{domain}", "*._domainkey", "TXT", "3600", "v=DKIM1; p=", "DKIM wildcard with empty key"],
    ["ADD", "{domain}", "_dmarc", "CNAME", "3600", "reject.dmarc.fabrikam.com.", "DMARC reject policy via CNAME"],
]


def generate_records(domain: str):
    records = [[f"--- {domain} ---", "", "", "", "", "", "Domain configuration"]]
    for template in RECORD_TEMPLATE:
        records.append([
            template[0],
            domain,
            template[2],
            template[3],
            template[4],
            template[5],
            template[6],
        ])
    return records


def main():
    if len(sys.argv) != 3:
        print("Usage: python parked_domain_csv.py domains.txt output.csv")
        sys.exit(1)

    domain_file = sys.argv[1]
    output_csv = sys.argv[2]

    with open(domain_file, "r", encoding="utf-8") as f:
        domains = [line.strip() for line in f if line.strip()]

    with open(output_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(HEADER)
        for domain in domains:
            for row in generate_records(domain):
                writer.writerow(row)


if __name__ == "__main__":
    main()
