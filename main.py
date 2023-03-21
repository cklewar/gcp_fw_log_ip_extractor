import json
import csv
import os
from ipwhois import IPWhois
from ipwhois.exceptions import HTTPLookupError, IPDefinedError

GCP_NEW_IP_PREFIXES_FILE = "input/gcp/downloaded-logs-20230314-234955.json"
AWS_NEW_IP_PREFIXES_FILE = ""
AWS_SG_GROUP_ACTION = "REJECT"
AWS_SG_GROUP_RULE_DESTINATION_PORT = "443"


def gcp():
    distinct_prefixes = set()
    seen_ips = set()

    with open("output/gcp/ip_prefixes.json", "r") as fp:
        ip_prefixes = json.load(fp=fp)

    with open(AWS_NEW_IP_PREFIXES_FILE, "r") as fp:
        new_ip_prefixes = json.load(fp=fp)

    for ip_prefix in new_ip_prefixes:
        ip_prefix = ip_prefix["jsonPayload"]["connection"]["dest_ip"].strip()
        if ip_prefix not in seen_ips:
            print(f'Working on IP prefix <{ip_prefix}>...')
            seen_ips.add(ip_prefix)
            try:
                obj = IPWhois(ip_prefix)
                try:
                    results = obj.lookup_rdap(depth=1)
                    cidr = results["network"]["cidr"]
                    if "," in cidr:
                        for elem in cidr.split(","):
                            distinct_prefixes.add(elem.strip())
                        print(f'Working on IP prefix <{ip_prefix}> --> Done')
                    else:
                        distinct_prefixes.add(cidr.strip())
                        print(f'Working on IP prefix <{ip_prefix}> --> Done')
                except HTTPLookupError as hle:
                    print(hle)
            except IPDefinedError as ide:
                print(ide)

    differences = distinct_prefixes.difference(set(ip_prefixes))
    print("New IP prefixes to add to IP prefix list:", differences)
    ip_prefixes.extend(list(differences))

    with open("output/gcp/ip_prefixes.json", "w") as fp:
        json.dump(list(ip_prefixes), fp, indent=4)


def aws():
    distinct_prefixes = set()
    seen_ips = set()
    obj = os.scandir(path="./input/aws")

    with open("output/aws/ip_prefixes.json", "r") as fp:
        ip_prefixes = json.load(fp=fp)

    for entry in obj:
        if entry.is_file() and entry.name.endswith(".log"):
            with open(f"./input/aws/{entry.name}", newline='') as fp:
                flows = csv.reader(fp, delimiter=' ', quotechar='|')
                for flow in flows:
                    if AWS_SG_GROUP_ACTION in flow and flow[6] == AWS_SG_GROUP_RULE_DESTINATION_PORT:
                        ip_prefix = flow[4].strip()
                        if ip_prefix not in seen_ips:
                            print(f'Working on IP prefix <{ip_prefix}>...')
                            seen_ips.add(ip_prefix)
                            try:
                                obj = IPWhois(ip_prefix)
                                try:
                                    results = obj.lookup_rdap(depth=1)
                                    cidr = results["network"]["cidr"]
                                    if "," in cidr:
                                        for elem in cidr.split(","):
                                            distinct_prefixes.add(elem.strip())
                                        print(f'Working on IP prefix <{ip_prefix}> --> Done')
                                    else:
                                        distinct_prefixes.add(cidr.strip())
                                        print(f'Working on IP prefix <{ip_prefix}> --> Done')
                                except HTTPLookupError as hle:
                                    print(hle)
                            except IPDefinedError as ide:
                                print(ide)

    differences = distinct_prefixes.difference(set(ip_prefixes))
    print("New IP prefixes to add to IP prefix list:", differences)
    ip_prefixes.extend(list(differences))

    with open("output/aws/ip_prefixes.json", "w") as fp:
        json.dump(list(ip_prefixes), fp, indent=4)


if __name__ == '__main__':
    aws()
