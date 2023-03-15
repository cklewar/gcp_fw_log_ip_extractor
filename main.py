import json
from ipwhois import IPWhois
from ipwhois.exceptions import HTTPLookupError, IPDefinedError


NEW_IP_PREFIXES_FILE = "input/downloaded-logs-20230314-234955.json"

if __name__ == '__main__':
    distinct_prefixes = set()
    seen_ips = set()

    with open("output/ip_prefixes.json", "r") as fp:
        ip_prefixes = json.load(fp=fp)

    with open(NEW_IP_PREFIXES_FILE, "r") as fp:
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

    with open("output/ip_prefixes.json", "w") as fp:
        json.dump(list(ip_prefixes), fp, indent=4)
