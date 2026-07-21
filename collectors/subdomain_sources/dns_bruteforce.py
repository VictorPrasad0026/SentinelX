import os
import dns.resolver

from concurrent.futures import ThreadPoolExecutor, as_completed



BASE_DIR = os.path.dirname(__file__)


WORDLIST = os.path.join(
    BASE_DIR,
    "wordlist.txt"
)



resolver = dns.resolver.Resolver()

resolver.timeout = 2
resolver.lifetime = 2





def load_wordlist():

    with open(
        WORDLIST,
        "r"
    ) as file:

        return [

            line.strip()

            for line in file

            if line.strip()

        ]






def resolve(host):

    result = {

        "host": host,

        "A": [],

        "AAAA": [],

        "CNAME": [],

        "sources": [
            "dns_bruteforce"
        ]

    }



    # A record

    try:

        answers = resolver.resolve(
            host,
            "A"
        )

        result["A"] = [

            str(x)

            for x in answers

        ]

    except:

        pass



    # AAAA record

    try:

        answers = resolver.resolve(
            host,
            "AAAA"
        )

        result["AAAA"] = [

            str(x)

            for x in answers

        ]

    except:

        pass



    # CNAME record

    try:

        answers = resolver.resolve(
            host,
            "CNAME"
        )

        result["CNAME"] = [

            str(x.target).rstrip(".")

            for x in answers

        ]

    except:

        pass




    if (

        result["A"]

        or

        result["AAAA"]

        or

        result["CNAME"]

    ):

        return result



    return None







def brute_force(domain):


    results=[]


    words = load_wordlist()



    with ThreadPoolExecutor(
        max_workers=100
    ) as executor:



        jobs = [

            executor.submit(

                resolve,

                f"{word}.{domain}"

            )

            for word in words

        ]



        for job in as_completed(jobs):

            data = job.result()


            if data:

                results.append(data)



    return results