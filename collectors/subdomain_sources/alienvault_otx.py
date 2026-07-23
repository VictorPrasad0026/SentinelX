import requests
import re
import time


USER_AGENT = {
    "User-Agent": "SentinelX-ASM-Engine/2.0"
}



def clean_hostname(host, domain):

    if not host:
        return None


    host = (
        host
        .lower()
        .strip()
    )


    host = host.replace(
        "*.",
        ""
    )


    if "@" in host:
        return None


    if not host.endswith(domain):

        return None


    if host == domain:

        return None


    pattern = r"^[a-z0-9.-]+\.[a-z]{2,}$"


    if not re.match(pattern, host):

        return None


    return host





def query_otx(domain):


    results=set()


    url = (
        "https://otx.alienvault.com/api/v1/indicators/domain/"
        f"{domain}/passive_dns"
    )



    try:


        response=requests.get(

            url,

            headers=USER_AGENT,

            timeout=20

        )



        if response.status_code != 200:


            print(
                "[OTX] HTTP",
                response.status_code
            )

            return results




        data=response.json()



        passive_dns=data.get(
            "passive_dns",
            []
        )



        for item in passive_dns:


            hostname=item.get(
                "hostname"
            )


            clean=clean_hostname(

                hostname,

                domain

            )


            if clean:

                results.add(clean)




    except requests.exceptions.Timeout:


        print(
            "[OTX] Timeout"
        )



    except Exception as e:


        print(
            "[OTX ERROR]",
            e
        )



    return results






def get_otx_subdomains(domain):


    print(
        "[+] Querying AlienVault OTX"
    )


    results=query_otx(
        domain
    )


    print(
        f"[+] OTX discovered {len(results)} hosts"
    )


    return results





if __name__=="__main__":


    target=input(
        "Enter domain: "
    ).strip().lower()



    hosts=get_otx_subdomains(
        target
    )



    print(
        "\n========== RESULTS ==========\n"
    )



    for host in sorted(hosts):

        print(host)



    print(
        "\nTotal:",
        len(hosts)
    )