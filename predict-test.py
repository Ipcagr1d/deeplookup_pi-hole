import csv
import dns.resolver
from deeplookup import Resolver

def get_potential_dga_domains():
    # Create a DeepLookup Resolver instance
    dl = Resolver()

    # Open the domains.csv file
    with open('domains.csv', 'r', encoding='utf-8') as domains_file:
        # Create a CSV reader object
        reader = csv.reader(domains_file)
        # Read all the rows from the CSV file
        domains = list(reader)

    # Create a list to store potential DGA domains
    potential_dga_domains = []

    # Iterate over each domain
    for domain in domains:
        domain = domain[0]
        try:
            # Verify the domain using DeepLookup
            dl.resolve(domain)
            # If the domain is resolved without exceptions, it is not a potential DGA domain
            continue
        except dns.resolver.NXDOMAIN:
            # If the domain does not exist (NXDOMAIN), it is a potential DGA domain
            potential_dga_domains.append(domain)
        except dns.exception.DNSException as e:
            # Handle any other DNS exceptions if necessary
            print(f"Error resolving domain {domain}: {e}")
            continue

    return potential_dga_domains

def update_blocklist(potential_dga_domains):
    # Write the potential DGA domains to the new blocklist file
    with open('custom_blocklist.txt', 'a+', encoding='utf-8') as blocklist_file:
        # Move file pointer to the beginning of the file
        blocklist_file.seek(0)
        # Read all existing entries in the blocklist file
        existing_entries = blocklist_file.readlines()
        for domain in potential_dga_domains:
            # Check if the entry already exists in the blocklist file before writing it
            if f'{domain}\n' not in existing_entries:
                blocklist_file.write(f'{domain}\n')

if __name__ == '__main__':
    potential_dga_domains = get_potential_dga_domains()
    update_blocklist(potential_dga_domains)