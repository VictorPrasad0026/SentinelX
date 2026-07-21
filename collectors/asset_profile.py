import json
import os

from datetime import datetime
import profile
from collectors.asset_graph import create_asset_graph


from collectors.domain_intelligence import get_domain_info
from collectors.dns_intelligence import get_dns_info
from collectors.ssl_intelligence import get_ssl_info
from collectors.subdomain_intelligence import get_subdomains
from collectors.technology_intelligence import get_technology_info
from collectors.csp_intelligence import analyze_csp
from collectors.risk_engine import calculate_risk




def generate_asset_profile(domain):


    profile = {


        "asset": domain,
        

        "scan_metadata": {


            "scan_time":
            datetime.utcnow().isoformat(),


            "scanner":
            "SentinelX Asset Intelligence Engine",


            "version":
            "0.4"


        },


        "domain_intelligence": {},
        "asset_graph":{},

        "dns_intelligence": {},


        "ssl_intelligence": {},


        "subdomain_intelligence": {},


        "technology_intelligence": {},


        "csp_intelligence": {},


        "risk_assessment": {}

    }




    print("\n[+] Collecting Domain Intelligence")

    profile["domain_intelligence"] = (

        get_domain_info(domain)

    )





    print("[+] Collecting DNS Intelligence")

    profile["dns_intelligence"] = (

        get_dns_info(domain)

    )





    print("[+] Collecting SSL Intelligence")

    profile["ssl_intelligence"] = (

        get_ssl_info(domain)

    )





    print("[+] Discovering Subdomains")

    profile["subdomain_intelligence"] = (

        get_subdomains(domain)

    )






    print("[+] Fingerprinting Technologies")

    technology = get_technology_info(domain)


    profile["technology_intelligence"] = technology





    print("[+] Analysing Content Security Policy")


    csp_data = technology.get(
        "csp_raw",
        {}
    )



    if csp_data.get("enabled"):


        profile["csp_intelligence"] = (

            analyze_csp(

                csp_data.get(
                    "value"
                )

            )

        )


    else:


        profile["csp_intelligence"] = {

            "enabled":False,

            "risk_level":"UNKNOWN",

            "message":
            "No CSP detected"

        }







    print("[+] Calculating Security Risk")


    profile["risk_assessment"] = (

        calculate_risk(profile)

    )
    
    print("[+] Building Asset Relationship Graph")


    profile["asset_graph"] = create_asset_graph(profile)




    return profile







def save_report(profile):


    os.makedirs(

        "reports",

        exist_ok=True

    )



    domain = profile["asset"]


    timestamp = datetime.now().strftime(

        "%Y%m%d_%H%M%S"

    )



    filename = (

        f"{domain}_{timestamp}.json"

    )



    filepath = os.path.join(

        "reports",

        filename

    )



    with open(

        filepath,

        "w"

    ) as file:



        json.dump(

            profile,

            file,

            indent=4

        )



    return filepath







if __name__ == "__main__":


    target=input(

        "Enter target domain: "

    )



    profile=generate_asset_profile(

        target

    )



    report=save_report(

        profile

    )



    print("\n================================")

    print(" SentinelX Security Report ")

    print("================================")



    print(

        "\nRisk Score:",

        profile["risk_assessment"].get(

            "risk_score"

        )

    )



    print(

        "Severity:",

        profile["risk_assessment"].get(

            "severity"

        )

    )



    print(

        "\nReport saved:",

        report

    )