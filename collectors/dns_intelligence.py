from datetime import datetime
import dns.resolver



def get_dns_info(domain):

    result = {

        "domain": domain,

        "timestamp":
        datetime.utcnow().isoformat(),

        "dns": {}

    }


    record_types = [
        "A",
        "MX",
        "NS"
    ]


    for record in record_types:

        try:

            answers = dns.resolver.resolve(
                domain,
                record
            )


            result["dns"][record] = [

                str(r)

                for r in answers

            ]


        except:

            result["dns"][record] = []



    return result





# ONLY FOR TERMINAL TESTING

if __name__ == "__main__":


    domain = input(
        "Enter domain: "
    )


    print(
        get_dns_info(domain)
    )