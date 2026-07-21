import socket
from datetime import datetime


def get_domain_info(domain):

    result = {
        "domain": domain,
        "timestamp": datetime.utcnow().isoformat(),
        "ip_addresses": []
    }

    try:
        addresses = socket.gethostbyname_ex(domain)

        result["ip_addresses"] = addresses[2]

    except socket.gaierror:

        result["error"] = "Domain resolution failed"

    return result


if __name__ == "__main__":

    target = input("Enter target domain: ")

    information = get_domain_info(target)

    print(information)