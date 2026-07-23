from datetime import datetime
from concurrent.futures import ThreadPoolExecutor


from collectors.subdomain_sources.crtsh import (
    get_ct_subdomains
)

from collectors.subdomain_sources.certspotter import (
    get_certspotter
)

from collectors.subdomain_sources.alienvault_otx import (
    get_otx_subdomains
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





# -------------------------------------------------
# DNS enrichment
# -------------------------------------------------

def enrich_hosts(hosts, source):


    results=[]


    for host in hosts:


        try:


            data=resolve(host)



            if data:


                data["source"]=source


                data.pop(
                    "sources",
                    None
                )


                results.append(data)



        except Exception:

            continue



    return results







# -------------------------------------------------
# Merge assets
# -------------------------------------------------

def merge_results(final, items):


    for item in items:


        host=item.get(
            "host"
        )


        if not host:

            continue




        if host in final:



            if "sources" not in final[host]:


                final[host]["sources"]=[

                    final[host].get(
                        "source"
                    )

                ]




            source=item.get(
                "source"
            )



            if source and source not in final[host]["sources"]:


                final[host]["sources"].append(
                    source
                )



        else:


            final[host]=item







# -------------------------------------------------
# Main Engine
# -------------------------------------------------

def get_subdomains(domain):


    result={


        "domain":domain,


        "timestamp":
        datetime.utcnow().isoformat()+"Z",



        "discovery":{


            "crtsh":0,

            "certspotter":0,

            "otx":0,

            "dns_bruteforce":0,

            "permutation":0,

            "recursive":0,

            "zone_transfer":0

        },



        "wildcard_dns":False,


        "total_subdomains":0,


        "subdomains":[]

    }




    final={}




    # -----------------------------
    # Wildcard
    # -----------------------------

    print(
        "[+] Checking wildcard DNS"
    )


    try:

        result["wildcard_dns"]=check_wildcard(
            domain
        )


    except Exception:

        result["wildcard_dns"]=False






    # -----------------------------
    # Parallel Discovery
    # -----------------------------


    print(
        "[+] Starting passive discovery"
    )



    with ThreadPoolExecutor(
        max_workers=6
    ) as executor:



        tasks={


            "crtsh":

            executor.submit(

                get_ct_subdomains,

                domain

            ),



            "certspotter":

            executor.submit(

                get_certspotter,

                domain

            ),




            "otx":

            executor.submit(

                get_otx_subdomains,

                domain

            ),




            "brute":

            executor.submit(

                brute_force,

                domain

            ),




            "recursive":

            executor.submit(

                recursive_discovery,

                domain

            ),




            "zone":

            executor.submit(

                check_zone_transfer,

                domain

            )

        }



        outputs={}



        for name,future in tasks.items():


            try:


                outputs[name]=future.result()



            except Exception as e:


                print(
                    f"[{name}] ERROR:",
                    e
                )


                outputs[name]=[]






    # -----------------------------
    # Extract results
    # -----------------------------


    ct_hosts=set(
        outputs.get(
            "crtsh",
            []
        )
    )



    cert_hosts=set(
        outputs.get(
            "certspotter",
            []
        )
    )



    otx_hosts=set(
        outputs.get(
            "otx",
            []
        )
    )



    brute_results=outputs.get(
        "brute",
        []
    )



    recursive_hosts=set(
        outputs.get(
            "recursive",
            []
        )
    )



    zone_hosts=set(
        outputs.get(
            "zone",
            []
        )
    )





    result["discovery"]["crtsh"]=len(
        ct_hosts
    )


    result["discovery"]["certspotter"]=len(
        cert_hosts
    )


    result["discovery"]["otx"]=len(
        otx_hosts
    )



    result["discovery"]["dns_bruteforce"]=len(
        brute_results
    )



    result["discovery"]["recursive"]=len(
        recursive_hosts
    )


    result["discovery"]["zone_transfer"]=len(
        zone_hosts
    )







    # -----------------------------
    # DNS brute force tagging
    # -----------------------------

    for item in brute_results:

        item["source"]="dns_bruteforce"





    brute_hosts={


        x["host"]

        for x in brute_results

        if "host" in x

    }







    # -----------------------------
    # Permutations
    # -----------------------------

    print(
        "[+] Generating permutations"
    )


    try:


        generated=generate_permutations(

            list(
                ct_hosts |
                cert_hosts |
                otx_hosts |
                brute_hosts
            ),

            domain

        )


    except Exception:


        generated=[]




    permutation_results=enrich_hosts(

        generated,

        "permutation"

    )



    result["discovery"]["permutation"]=len(
        permutation_results
    )






    # -----------------------------
    # Recursive enrichment
    # -----------------------------


    recursive_results=enrich_hosts(

        recursive_hosts,

        "recursive"

    )






    # -----------------------------
    # Zone enrichment
    # -----------------------------


    zone_results=enrich_hosts(

        zone_hosts,

        "zone_transfer"

    )







    # -----------------------------
    # Merge
    # -----------------------------


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






    # -----------------------------
    # Passive sources only
    # -----------------------------


    passive_sources=[

        ("crtsh",ct_hosts),

        ("certspotter",cert_hosts),

        ("otx",otx_hosts)

    ]




    for source,hosts in passive_sources:


        for host in hosts:



            if host not in final:


                final[host]={


                    "host":host,

                    "A":[],

                    "AAAA":[],

                    "CNAME":[],

                    "source":source,

                    "resolution_status":
                    "unresolved"

                }



            else:


                if "sources" not in final[host]:

                    final[host]["sources"]=[]



                if source not in final[host]["sources"]:


                    final[host]["sources"].append(
                        source
                    )








    # -----------------------------
    # Final response
    # -----------------------------


    result["subdomains"]=list(
        final.values()
    )



    result["subdomains"].sort(

        key=lambda x:x["host"]

    )



    result["total_subdomains"]=len(

        result["subdomains"]

    )



    return result







# -------------------------------------------------
# Test
# -------------------------------------------------

if __name__=="__main__":


    domain=input(
        "Enter domain: "
    ).strip().lower()



    data=get_subdomains(
        domain
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



    print(
        "\nSubdomains:\n"
    )


    for item in data["subdomains"]:


        print(

            item["host"],

            "=>",

            item.get(
                "sources",
                item.get(
                    "source"
                )
            )

        )