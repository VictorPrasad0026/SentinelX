from collectors.subdomain_sources.crtsh import (
    get_ct_subdomains
)



def recursive_discovery(domain):

    discovered = set()


    try:

        print(
            "[+] Recursive CT discovery"
        )


        # First level discovery

        first_level = get_ct_subdomains(
            domain
        )



        for sub in first_level:


            if sub not in discovered:

                discovered.add(
                    sub
                )



            try:

                # Nested subdomain discovery

                children = get_ct_subdomains(
                    sub
                )


                for child in children:


                    if child not in discovered:

                        discovered.add(
                            child
                        )



            except Exception:

                pass




    except Exception as e:


        print(
            "[RECURSIVE ERROR]",
            e
        )



    return discovered