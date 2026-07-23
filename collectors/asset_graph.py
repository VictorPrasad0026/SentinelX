
import uuid
from datetime import datetime



# ==========================================
# NODE CREATOR
# ==========================================

def create_node(
        node_type,
        name,
        properties=None
):

    return {

        "id":
        str(uuid.uuid4()),


        "type":
        node_type,


        "name":
        name,


        "properties":
        properties or {}

    }





# ==========================================
# EDGE CREATOR
# ==========================================

def create_edge(
        source,
        target,
        relation
):

    return {


        "source":
        source,


        "target":
        target,


        "relation":
        relation


    }





# ==========================================
# ASSET GRAPH ENGINE
# ==========================================

def create_asset_graph(profile):


    nodes=[]

    edges=[]



    # ======================================
    # Organization Root
    # ======================================


    domain = profile.get(
        "asset"
    )


    org_node=create_node(

        "Organization",

        domain

    )


    nodes.append(org_node)





    # ======================================
    # Domain
    # ======================================


    domain_node=create_node(

        "Domain",

        domain,

        profile.get(
            "domain_intelligence",
            {}
        )

    )


    nodes.append(domain_node)



    edges.append(

        create_edge(

            org_node["id"],

            domain_node["id"],

            "owns"

        )

    )





    # ======================================
    # DNS
    # ======================================


    dns=profile.get(

        "dns_intelligence",

        {}

    )


    for ip in dns.get(
        "A",
        []
    ):


        ip_node=create_node(

            "IPv4",

            ip

        )


        nodes.append(ip_node)



        edges.append(

            create_edge(

                domain_node["id"],

                ip_node["id"],

                "resolves_to"

            )

        )





    # ======================================
    # SSL Certificate
    # ======================================


    ssl=profile.get(

        "ssl_intelligence",

        {}

    )


    if ssl:


        cert_node=create_node(

            "Certificate",

            ssl.get(
                "issuer",
                "Unknown"
            ),

            ssl

        )


        nodes.append(cert_node)



        edges.append(

            create_edge(

                domain_node["id"],

                cert_node["id"],

                "uses_certificate"

            )

        )







    # ======================================
    # Technologies
    # ======================================


    technologies=profile.get(

        "technology_intelligence",

        {}

    ).get(

        "technologies",

        []

    )




    for tech in technologies:


        tech_node=create_node(

            "Technology",

            tech

        )


        nodes.append(tech_node)



        edges.append(

            create_edge(

                domain_node["id"],

                tech_node["id"],

                "runs"

            )

        )







    # ======================================
    # Subdomains
    # ======================================


    assets=profile.get(

        "subdomain_assets",

        {}

    ).get(

        "assets",

        []

    )





    for asset in assets:


        host=asset.get(

            "host"

        )



        sub_node=create_node(

            "Subdomain",

            host,

            {

                "risk":
                asset.get(
                    "risk",
                    {}
                ),

                "dns":
                asset.get(
                    "dns",
                    {}
                )

            }

        )


        nodes.append(sub_node)



        edges.append(

            create_edge(

                domain_node["id"],

                sub_node["id"],

                "contains"

            )

        )




        # IP relationship


        for ip in asset.get(

            "dns",

            {}

        ).get(

            "A",

            []

        ):


            ip_node=create_node(

                "IPv4",

                ip

            )


            nodes.append(ip_node)



            edges.append(

                create_edge(

                    sub_node["id"],

                    ip_node["id"],

                    "resolves_to"

                )

            )





        # Technology relationship


        for tech in asset.get(

            "http",

            {}

        ).get(

            "technologies",

            []

        ):


            tech_node=create_node(

                "Technology",

                tech

            )


            nodes.append(tech_node)



            edges.append(

                create_edge(

                    sub_node["id"],

                    tech_node["id"],

                    "uses"

                )

            )







    # ======================================
    # Risk Node
    # ======================================


    risk=profile.get(

        "risk_assessment",

        {}

    )


    risk_node=create_node(

        "Risk",

        "Security Risk",

        risk

    )


    nodes.append(risk_node)



    edges.append(

        create_edge(

            domain_node["id"],

            risk_node["id"],

            "has_risk"

        )

    )







    return {


        "graph_metadata":{


            "engine":

            "SentinelX Asset Graph Engine",


            "version":

            "1.0",


            "created":

            datetime.utcnow().isoformat()+"Z"


        },


        "nodes":

        nodes,


        "edges":

        edges,


        "statistics":{


            "nodes":

            len(nodes),


            "edges":

            len(edges)

        }

    }






if __name__=="__main__":

    print(
        "SentinelX Asset Graph Engine v1 Loaded"
    )
