import requests
import time
import re


USER_AGENT = {
    "User-Agent": "SentinelX-ASM-Engine/2.0"
}


CRT_ENDPOINTS = [
    "https://crt.sh/?q=%25.{domain}&output=json",
    "https://crt.sh/?q={domain}&output=json"
]


def clean_hostname(name, domain):

    if not name:
        return None


    name = (
        name
        .lower()
        .strip()
    )


    # Remove wildcard
    name = name.replace("*.", "")


    # Remove invalid entries
    if (
        "@" in name
        or " "
        in name
    ):
        return None


    # Must belong to target domain

    if not name.endswith(domain):
        return None


    # Remove root domain

    if name == domain:
        return None



    hostname_regex = (
        r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$"
    )


    if not re.match(
        hostname_regex,
        name
    ):
        return None


    return name





def request_crt(url):


    session = requests.Session()

    session.headers.update(
        USER_AGENT
    )


    retries = 4


    for attempt in range(retries):

        try:


            response = session.get(

                url,

                timeout=15

            )


            if response.status_code == 200:


                try:

                    return response.json()

                except Exception:

                    print(
                        "[CRT] Invalid JSON response"
                    )

                    return []



            else:


                print(
                    f"[CRT] HTTP {response.status_code}"
                )



        except requests.exceptions.Timeout:


            print(
                f"[CRT] Timeout attempt {attempt+1}/{retries}"
            )



        except requests.exceptions.RequestException as e:


            print(
                "[CRT NETWORK]",
                e
            )



        # exponential backoff

        time.sleep(
            2 ** attempt
        )



    return []








def query_crtsh(domain):


    discovered=set()



    for endpoint in CRT_ENDPOINTS:


        url = endpoint.format(
            domain=domain
        )


        print(
            "[CRT] Query:",
            url
        )



        data=request_crt(url)



        if not data:

            continue



        for certificate in data:


            names = certificate.get(
                "name_value",
                ""
            )


            for name in names.split("\n"):


                host = clean_hostname(

                    name,

                    domain

                )


                if host:

                    discovered.add(
                        host
                    )



    return discovered









def get_ct_subdomains(domain):


    print(
        "[+] Querying CRT.sh"
    )


    results=query_crtsh(
        domain
    )



    print(
        f"[+] CRT.sh discovered {len(results)} hosts"
    )



    return results







if __name__ == "__main__":


    target=input(
        "Enter domain: "
    ).strip().lower()



    results=get_ct_subdomains(
        target
    )


    print(
        "\n========== RESULTS ==========\n"
    )


    for host in sorted(results):

        print(host)



    print(
        "\nTotal:",
        len(results)
    )