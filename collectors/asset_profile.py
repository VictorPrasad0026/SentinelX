import json
import os
import time

from datetime import datetime


from collectors.infrastructure_intelligence import (
    get_infrastructure_info
)

from collectors.email_intelligence import (
    get_email_intelligence
)

from collectors.asset_graph import (
    create_asset_graph
)

from collectors.domain_intelligence import (
    get_domain_info
)

from collectors.dns_intelligence import (
    get_dns_info
)

from collectors.ssl_intelligence import (
    get_ssl_info
)

from collectors.subdomain_intelligence import (
    get_subdomains
)

from collectors.subdomain_asset_enrichment import (
    enrich_all_subdomains
)

from collectors.technology_intelligence import (
    get_technology_info
)

from collectors.csp_intelligence import (
    analyze_csp
)

from collectors.risk_engine import (
    calculate_risk
)





# ==========================================
# SAFE COLLECTOR EXECUTION
# ==========================================

def run_collector(name, func, *args):

    try:

        print(f"[+] {name}")

        start = time.time()


        result = func(*args)


        elapsed = round(
            time.time() - start,
            2
        )


        print(
            f"[✓] {name} completed ({elapsed}s)"
        )


        return result



    except Exception as e:


        print(
            f"[!] {name} failed:",
            e
        )


        return {

            "error": str(e)

        }







# ==========================================
# ATTACK SURFACE SUMMARY
# ==========================================


def build_attack_surface(profile):


    assets = profile.get(
        "subdomain_assets",
        {}
    ).get(
        "assets",
        []
    )



    summary = {


        "total_subdomains":

        profile.get(
            "subdomain_intelligence",
            {}
        ).get(
            "total_subdomains",
            0
        ),



        "resolved_assets":

        len(assets),



        "technologies":

        profile.get(
            "technology_intelligence",
            {}
        ).get(
            "technologies",
            []
        ),



        "email_provider":

        profile.get(
            "email_intelligence",
            {}
        )
        .get(
            "mx",
            {}
        )
        .get(
            "provider"
        ),



        "email_risk":

        profile.get(
            "email_intelligence",
            {}
        )
        .get(
            "risk",
            {}
        )
        .get(
            "score"
        ),



        "waf_detected":False,


        "invalid_ssl_assets":[],

        "missing_csp_assets":[],
        

        "sensitive_assets":[]

    }





    for asset in assets:


        host = asset.get(
            "host",
            ""
        )


        ssl = asset.get(
            "ssl",
            {}
        )


        http = asset.get(
            "http",
            {}
        )


        risk = asset.get(
            "risk",
            {}
        )



        if ssl.get(
            "status"
        ) != "VALID":


            summary[
                "invalid_ssl_assets"
            ].append(
                host
            )




            security_headers = http.get(
                "security_headers",
                {}
            )


            csp_header = security_headers.get(
                "content-security-policy",
                {}
            )


            if csp_header.get(
                "present",
                False
            ) == False:


                summary[
                    "missing_csp_assets"
                ].append(
                    host
                )

            if http.get(
                "waf",
                {}
            ).get(
                "detected"
            ):


                summary[
                    "waf_detected"
                ] = True






        for finding in risk.get(
            "findings",
            []
        ):


            if "Sensitive hostname" in finding.get(
                "issue",
                ""
            ):


                summary[
                    "sensitive_assets"
                ].append(
                    host
                )



    return summary








# ==========================================
# MAIN ASSET PROFILE ENGINE
# ==========================================


def generate_asset_profile(domain):


    start = time.time()



    profile = {


        "asset":domain,



        "scan_metadata":{


            "scan_time":
            datetime.utcnow().isoformat()+"Z",


            "scanner":
            "SentinelX Asset Intelligence Engine",


            "version":
            "1.2"


        },



        "domain_intelligence":{},


        "dns_intelligence":{},


        "email_intelligence":{},
        
        "infrastructure_intelligence": {},


        "ssl_intelligence":{},


        "technology_intelligence":{},


        "csp_intelligence":{},


        "subdomain_intelligence":{},


        "subdomain_assets":{},


        "risk_assessment":{},


        "asset_graph":{},


        "attack_surface":{}


    }





    # Domain

    profile[
        "domain_intelligence"
    ] = run_collector(

        "Domain Intelligence",

        get_domain_info,

        domain

    )





    # DNS

    profile[
        "dns_intelligence"
    ] = run_collector(

        "DNS Intelligence",

        get_dns_info,

        domain

    )





    # Email

    profile[
        "email_intelligence"
    ] = run_collector(

        "Email Security Intelligence",

        get_email_intelligence,

        domain

    )





    # SSL

    profile[
        "ssl_intelligence"
    ] = run_collector(

        "SSL Intelligence",

        get_ssl_info,

        domain

    )
    
    profile["infrastructure_intelligence"] = run_collector(

    "Infrastructure Intelligence",

    get_infrastructure_info,

    domain

)
        # ==================================
    # Technology Intelligence
    # ==================================

    technology = run_collector(

        "Technology Fingerprinting",

        get_technology_info,

        domain

    )


    profile[
        "technology_intelligence"
    ] = technology





 # ==================================
# CSP Intelligence
# ==================================

    print("[+] CSP Analysis")


    try:


        csp_raw = technology.get(
            "csp_raw",
            {}
        )


        # New format
        if isinstance(csp_raw, dict):


            csp_enabled = csp_raw.get(
                "enabled",
                False
            )


            csp_value = csp_raw.get(
                "value"
            )


        # Backward compatibility
        else:


            csp_enabled = True

            csp_value = csp_raw




        if csp_enabled and csp_value:


            profile[
                "csp_intelligence"
            ] = analyze_csp(

                csp_value

            )



        else:


            profile[
                "csp_intelligence"
            ] = {


                "enabled": False,


                "risk_level": "UNKNOWN",


                "directives": {},


                "trusted_domains": [],


                "message":
                "Content Security Policy not detected"


            }




    except Exception as e:


        profile[
            "csp_intelligence"
        ] = {


            "enabled": False,


            "risk_level":"ERROR",


            "error":str(e)

        }




    # ==================================
    # Subdomain Discovery
    # ==================================

    subdomains = run_collector(

        "Subdomain Discovery",

        get_subdomains,

        domain

    )


    profile[
        "subdomain_intelligence"
    ] = subdomains







    # ==================================
    # Subdomain Asset Enrichment
    # ==================================

    if (

        isinstance(

            subdomains,

            dict

        )

        and

        subdomains.get(
            "subdomains"
        )

    ):


        profile[
            "subdomain_assets"
        ] = run_collector(

            "Subdomain Enrichment",

            enrich_all_subdomains,

            subdomains

        )



    else:


        profile[
            "subdomain_assets"
        ] = {


            "total_assets":0,


            "assets":[]

        }







    # ==================================
    # Risk Engine
    # ==================================

    profile[
        "risk_assessment"
    ] = run_collector(

        "Risk Engine",

        calculate_risk,

        profile

    )








    # ==================================
    # Asset Relationship Graph
    # ==================================

    profile[
        "asset_graph"
    ] = run_collector(

        "Asset Graph",

        create_asset_graph,

        profile

    )







    # ==================================
    # Attack Surface Summary
    # ==================================

    profile[
        "attack_surface"
    ] = build_attack_surface(

        profile

    )





    profile[
        "scan_metadata"
    ][
        "duration_seconds"
    ] = round(

        time.time()-start,

        2

    )



    return profile










# ==========================================
# SAVE JSON REPORT
# ==========================================


def save_report(profile):


    os.makedirs(

        "reports",

        exist_ok=True

    )



    filename = (

        f"{profile['asset']}_"

        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        ".json"

    )



    path = os.path.join(

        "reports",

        filename

    )





    with open(

        path,

        "w",

        encoding="utf-8"

    ) as file:


        json.dump(

            profile,

            file,

            indent=4

        )



    return path











# ==========================================
# CLI TEST
# ==========================================


if __name__ == "__main__":


    target = input(

        "Enter target domain: "

    ).strip().lower()



    result = generate_asset_profile(

        target

    )



    report = save_report(

        result

    )




    print("\n==============================")

    print(" SentinelX Security Report ")

    print("==============================")



    print(

        "Risk:",

        result[
            "risk_assessment"
        ].get(

            "risk_score"

        )

    )



    print(

        "Severity:",

        result[
            "risk_assessment"
        ].get(

            "severity"

        )

    )



    print(

        "Subdomains:",

        result[
            "attack_surface"
        ].get(

            "total_subdomains"

        )

    )



    print(

        "Assets:",

        result[
            "attack_surface"
        ].get(

            "resolved_assets"

        )

    )



    print(

        "Email Provider:",

        result[
            "attack_surface"
        ].get(

            "email_provider"

        )

    )



    print(

        "Email Risk:",

        result[
            "attack_surface"
        ].get(

            "email_risk"

        )

    )



    print(

        "Scan Time:",

        result[
            "scan_metadata"
        ].get(

            "duration_seconds"

        ),

        "seconds"

    )



    print(

        "\nReport:",

        report

    )