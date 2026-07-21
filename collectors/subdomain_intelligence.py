from datetime import datetime


from collectors.subdomain_sources.crtsh import (
    get_ct_subdomains
)

from collectors.subdomain_sources.dns_bruteforce import (
    brute_force,
    resolve
)

from collectors.subdomain_sources.permutation import (
    generate_permutations
)

from collectors.subdomain_sources.wildcard import (
    check_wildcard
)

from collectors.subdomain_sources.dns_zone_transfer import (
    check_zone_transfer
)

from collectors.subdomain_sources.recursive import (
    recursive_discovery
)



def enrich_hosts(hosts, source):

    results = []


    for host in hosts:

        try:

            data = resolve(host)


            if data:

                data["source"] = source

                results.append(data)


        except Exception:

            pass


    return results





def merge_results(final, items):


    for item in items:

        host = item["host"]


        if host in final:

            if "sources" not in final[host]:

                final[host]["sources"] = [
                    final[host].get("source")
                ]


            final[host]["sources"].append(
                item.get("source")
            )


        else:

            final[host] = item





def get_subdomains(domain):


    result = {


        "domain": domain,


        "timestamp":
        datetime.utcnow().isoformat()+"Z",



        "discovery": {


            "crtsh":0,

            "dns_bruteforce":0,

            "permutation":0,

            "recursive":0,

            "zone_transfer":0

        },



        "wildcard_dns":False,


        "total_subdomains":0,


        "subdomains":[]

    }



    final = {}





    #
    # Wildcard
    #

    print("[+] Checking wildcard DNS")


    try:

        result["wildcard_dns"] = check_wildcard(domain)

    except Exception:

        result["wildcard_dns"] = False





    #
    # CRT.SH
    #

    print("[+] Certificate Transparency scan")


    try:

        ct_hosts = get_ct_subdomains(domain)


    except Exception:

        ct_hosts=set()



    result["discovery"]["crtsh"] = len(ct_hosts)







    #
    # DNS Bruteforce
    #

    print("[+] DNS enumeration")


    try:

        brute_results = brute_force(domain)


        for item in brute_results:

            item["source"]="dns_bruteforce"


    except Exception:

        brute_results=[]



    result["discovery"]["dns_bruteforce"] = len(
        brute_results
    )



    brute_hosts={

        x["host"]

        for x in brute_results

    }







    #
    # Permutation
    #

    print("[+] Generating permutations")


    try:

        generated = generate_permutations(

            list(ct_hosts)+list(brute_hosts),

            domain

        )


    except Exception:

        generated=[]




    permutation_results = enrich_hosts(

        generated,

        "permutation"

    )



    result["discovery"]["permutation"] = len(
        permutation_results
    )








    #
    # Recursive
    #

    print("[+] Recursive discovery")


    try:

        recursive_hosts = recursive_discovery(
            domain
        )


    except Exception:

        recursive_hosts=set()



    recursive_results = enrich_hosts(

        recursive_hosts,

        "recursive"

    )


    result["discovery"]["recursive"] = len(
        recursive_results
    )









    #
    # Zone Transfer
    #

    print("[+] Checking zone transfer")


    try:

        zone_hosts = check_zone_transfer(
            domain
        )


    except Exception:

        zone_hosts=set()



    zone_results = enrich_hosts(

        zone_hosts,

        "zone_transfer"

    )


    result["discovery"]["zone_transfer"] = len(
        zone_results
    )









    #
    # Merge DNS resolved assets
    #

    merge_results(
        final,
        brute_results
    )


    merge_results(
        final,
        permutation_results
    )


    merge_results(
        final,
        recursive_results
    )


    merge_results(
        final,
        zone_results
    )









    #
    # Add CT domains
    # Even if DNS fails
    #

    for host in ct_hosts:


        if host not in final:


            final[host]={


                "host":host,


                "A":[],


                "AAAA":[],


                "CNAME":[],


                "source":"crtsh",


                "resolution_status":
                "unresolved"


            }


        else:


            if "sources" not in final[host]:

                final[host]["sources"]=[]


            final[host]["sources"].append(
                "crtsh"
            )









    result["subdomains"] = list(
        final.values()
    )



    result["subdomains"].sort(
        key=lambda x:x["host"]
    )



    result["total_subdomains"] = len(
        result["subdomains"]
    )



    return result







if __name__=="__main__":


    target=input(
        "Enter domain: "
    ).strip().lower()



    data=get_subdomains(
        target
    )



    print(
        "\n========== RESULT ==========\n"
    )


    print(
        "Total:",
        data["total_subdomains"]
    )


    print(
        "\nDiscovery:",
        data["discovery"]
    )



    print("\nSubdomains:\n")


    for sub in data["subdomains"]:


        print(
            sub["host"],
            "=>",
            sub.get("source")
        )