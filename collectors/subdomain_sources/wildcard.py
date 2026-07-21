import random
import dns.resolver



def check_wildcard(domain):

    random_name = (
        f"{random.randint(100000,999999)}.{domain}"
    )


    try:

        dns.resolver.resolve(
            random_name,
            "A"
        )

        return True


    except:

        return False