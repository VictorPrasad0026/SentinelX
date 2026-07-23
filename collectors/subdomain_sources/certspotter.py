import requests
import re



HEADERS = {
    "User-Agent":
    "SentinelX-V2 Subdomain Intelligence"
}



def clean_hostname(name, domain):

    if not name:
        return None


    name=name.lower().strip()


    name=name.replace(
        "*.",
        ""
    )


    if "@" in name:
        return None


    if not name.endswith(domain):
        return None


    if name == domain:
        return None


    if not re.match(
        r"^[a-z0-9.-]+\.[a-z]{2,}$",
        name
    ):
        return None


    return name





def get_certspotter(domain):


    print(
        "[+] Querying CertSpotter"
    )


    results=set()



    url=(
        "https://api.certspotter.com/v1/issuances"
        f"?domain={domain}"
        "&include_subdomains=true"
        "&expand=dns_names"
    )


    try:


        response=requests.get(

            url,

            headers=HEADERS,

            timeout=15

        )



        if response.status_code != 200:

            print(
                "[CertSpotter]",
                response.status_code
            )

            return results




        data=response.json()



        for cert in data:


            names=cert.get(
                "dns_names",
                []
            )


            for name in names:


                host=clean_hostname(

                    name,

                    domain

                )


                if host:

                    results.add(host)




    except Exception as e:


        print(
            "[CERTSPOTTER ERROR]",
            e
        )



    print(
        f"[+] CertSpotter discovered {len(results)} hosts"
    )


    return results