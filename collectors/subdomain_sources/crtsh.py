import requests
import time
import re


USER_AGENT = {
    "User-Agent": "SentinelX-V2 Subdomain Intelligence Engine"
}



def clean_hostname(name, domain):

    if not name:
        return None


    name = (
        name
        .lower()
        .strip()
    )


    # remove wildcard
    name = name.replace(
        "*.",
        ""
    )


    # remove emails
    if "@" in name:
        return None


    # remove spaces
    if " " in name:
        return None



    # must belong to target domain

    if not name.endswith(domain):

        return None



    # ignore root

    if name == domain:

        return None



    pattern = (
        r"^[a-z0-9.-]+\.[a-z]{2,}$"
    )


    if not re.match(
        pattern,
        name
    ):

        return None



    return name






def query_crtsh(domain):


    results=set()


    urls=[


        # wildcard search

        f"https://crt.sh/?q=%25.{domain}&output=json",


        # normal search

        f"https://crt.sh/?q={domain}&output=json"

    ]



    for url in urls:


        for attempt in range(3):

            try:


                response=requests.get(

                    url,

                    headers=USER_AGENT,

                    timeout=20

                )



                if response.status_code != 200:


                    print(
                        f"[CRT] HTTP {response.status_code} retry {attempt+1}"
                    )


                    time.sleep(3)

                    continue




                data=response.json()



                for cert in data:


                    names = cert.get(
                        "name_value",
                        ""
                    )



                    for name in names.split("\n"):


                        clean = clean_hostname(

                            name,

                            domain

                        )


                        if clean:

                            results.add(
                                clean
                            )



                return results



            except requests.exceptions.RequestException as e:


                print(
                    "[CRT NETWORK]",
                    e
                )


                time.sleep(3)



            except Exception as e:


                print(
                    "[CRT ERROR]",
                    e
                )



    return results







def get_ct_subdomains(domain):


    print(
        "[+] Querying CRT.sh"
    )


    results = query_crtsh(
        domain
    )



    print(
        f"[+] CRT.sh discovered {len(results)} hosts"
    )


    return results







if __name__=="__main__":


    target=input(
        "Enter domain: "
    ).strip().lower()



    subs=get_ct_subdomains(
        target
    )



    print("\nFound:\n")


    for sub in sorted(subs):

        print(sub)