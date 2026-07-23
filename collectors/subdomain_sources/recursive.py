from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests


USER_AGENT = {
    "User-Agent":
    "SentinelX-V2 Asset Intelligence Engine"
}


def clean_hostname(host, root_domain):

    if not host:
        return None


    host = (
        host
        .strip()
        .lower()
    )


    host = host.replace(
        "*.",
        ""
    )


    if "@" in host:
        return None


    if "://" in host:

        try:

            host = (
                urlparse(host)
                .hostname
            )

        except Exception:

            return None


    if not host:
        return None


    if host == root_domain:
        return None


    if not host.endswith(
        f".{root_domain}"
    ):

        return None


    return host



def query_hackertarget(domain):

    discovered = set()


    url = (
        "https://api.hackertarget.com/"
        f"hostsearch/?q={domain}"
    )


    try:

        response = requests.get(

            url,

            headers=USER_AGENT,

            timeout=8

        )


        if response.status_code != 200:

            return discovered


        for line in response.text.splitlines():

            host = (
                line
                .split(",")[0]
                .strip()
            )


            clean = clean_hostname(

                host,

                domain

            )


            if clean:

                discovered.add(
                    clean
                )


    except Exception:

        pass


    return discovered



def query_rapiddns(domain):

    discovered = set()


    url = (
        "https://rapiddns.io/"
        f"subdomain/{domain}"
        "?full=1"
    )


    try:

        response = requests.get(

            url,

            headers=USER_AGENT,

            timeout=8

        )


        if response.status_code != 200:

            return discovered


        text = response.text


        possible_hosts = (

            text
            .replace(
                '"',
                " "
            )
            .replace(
                "'",
                " "
            )
            .split()

        )


        for value in possible_hosts:

            value = value.strip(
                "<>/=,"
            )


            clean = clean_hostname(

                value,

                domain

            )


            if clean:

                discovered.add(
                    clean
                )


    except Exception:

        pass


    return discovered



def recursive_discovery(
    domain,
    seed_hosts=None,
    max_depth=1,
    max_queries=10
):

    """
    Passive source expansion.

    This function no longer recursively queries CRT.sh.

    CRT.sh is already used once by the main
    subdomain intelligence pipeline.

    Instead, independent passive sources are
    queried in parallel with short timeouts.
    """


    domain = (

        domain
        .strip()
        .lower()

    )


    print(

        "[+] Passive source expansion"

    )


    sources = [

        query_hackertarget,

        query_rapiddns

    ]


    discovered = set()


    with ThreadPoolExecutor(

        max_workers=2

    ) as executor:


        futures = [

            executor.submit(

                source,

                domain

            )

            for source in sources

        ]


        for future in futures:


            try:


                results = (

                    future.result(
                        timeout=10
                    )

                )


                discovered.update(

                    results

                )


            except Exception:


                pass


    print(

        "[+] Passive expansion discovered",

        len(discovered),

        "hosts"

    )


    return discovered