from datetime import datetime




def create_asset_graph(profile):


    graph = {

        "timestamp":
        datetime.utcnow().isoformat(),

        "nodes":[],

        "edges":[]

    }



    def add_node(node_id,node_type):


        graph["nodes"].append({

            "id":node_id,

            "type":node_type

        })



    def add_edge(source,target,relation):


        graph["edges"].append({

            "source":source,

            "target":target,

            "relationship":relation

        })




    domain = profile["asset"]



    # Main domain

    add_node(

        domain,

        "domain"

    )




    #
    # IP relationships
    #

    ips = profile.get(
        "domain_intelligence",
        {}
    ).get(
        "ip_addresses",
        []
    )


    for ip in ips:


        add_node(

            ip,

            "ip"

        )


        add_edge(

            domain,

            ip,

            "resolves_to"

        )





    #
    # Subdomains
    #

    subdomains = profile.get(

        "subdomain_intelligence",

        {}

    ).get(

        "subdomains",

        []

    )




    for sub in subdomains:


        host=sub.get(
            "host"
        )


        if host:


            add_node(

                host,

                "subdomain"

            )


            add_edge(

                domain,

                host,

                "contains"

            )



            for ip in sub.get(
                "A",
                []
            ):


                add_node(

                    ip,

                    "ip"

                )


                add_edge(

                    host,

                    ip,

                    "resolves_to"

                )





    #
    # Technology
    #

    tech = profile.get(

        "technology_intelligence",

        {}

    ).get(

        "technology",

        {}

    ).get(

        "detected_frameworks",

        []

    )



    for item in tech:


        add_node(

            item,

            "technology"

        )


        add_edge(

            domain,

            item,

            "uses"

        )




    #
    # WAF/CDN
    #

    protection = profile.get(

        "technology_intelligence",

        {}

    ).get(

        "protection",

        {})



    if protection.get(

        "detected"

    ):


        waf = protection.get(

            "type"

        )


        add_node(

            waf,

            "security_layer"

        )


        add_edge(

            domain,

            waf,

            "protected_by"

        )




    return graph