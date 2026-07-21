from datetime import datetime
from urllib.parse import urlparse



IMPORTANT_DIRECTIVES = [

    "default-src",

    "script-src",

    "style-src",

    "img-src",

    "connect-src",

    "frame-src",

    "object-src",

    "font-src"

]





def parse_directives(csp):


    directives = {}



    parts = csp.split(";")



    for part in parts:


        part = part.strip()



        if not part:

            continue



        tokens = part.split()



        directive = tokens[0]


        values = tokens[1:]



        directives[directive] = values



    return directives





def extract_domains(directives):


    domains = []



    for directive, values in directives.items():


        for value in values:


            value = value.strip()



            if value.startswith("'"):

                continue



            if value in [

                "data:",

                "blob:"

            ]:

                continue



            if value.startswith("http"):


                parsed = urlparse(value)


                if parsed.netloc:

                    domains.append(
                        parsed.netloc
                    )



            elif "." in value:


                domains.append(
                    value
                )



    return list(
        set(domains)
    )





def analyze_csp(csp_value, domain=None):


    result = {


        "domain":
        domain,


        "timestamp":
        datetime.utcnow().isoformat(),



        # Evidence

        "raw_csp":
        csp_value,



        "enabled":
        False,



        "directives":
        {},



        "security_analysis":
        {



            "unsafe_inline":
            False,



            "unsafe_eval":
            False,



            "wildcard_source":
            False,



            "missing_object_src":
            False

        },



        "third_party_domains":
        [],



        "domain_count":
        0,



        "findings":
        [],



        "risk_score":
        0,


        "risk_level":
        "UNKNOWN"

    }





    if not csp_value:


        result["findings"].append({

            "issue":
            "Missing Content Security Policy",

            "severity":
            "MEDIUM",

            "impact":
            "Reduced browser-side protection against injection attacks"

        })


        result["risk_score"] = 20


        result["risk_level"] = "MEDIUM"



        return result





    result["enabled"] = True




    directives = parse_directives(
        csp_value
    )


    result["directives"] = directives





    # unsafe-inline


    all_values = str(
        directives
    )



    if "'unsafe-inline'" in all_values:


        result["security_analysis"]["unsafe_inline"] = True


        result["risk_score"] += 20



        result["findings"].append({

            "issue":
            "unsafe-inline enabled",

            "severity":
            "MEDIUM",

            "impact":
            "Allows inline scripts/styles which can increase XSS impact"

        })






    # unsafe-eval


    if "'unsafe-eval'" in all_values:


        result["security_analysis"]["unsafe_eval"] = True


        result["risk_score"] += 25



        result["findings"].append({

            "issue":
            "unsafe-eval enabled",

            "severity":
            "HIGH",

            "impact":
            "Allows dynamic JavaScript evaluation"

        })







    # wildcard


    if "*" in all_values:


        result["security_analysis"]["wildcard_source"] = True


        result["risk_score"] += 15



        result["findings"].append({

            "issue":
            "Wildcard source detected",

            "severity":
            "MEDIUM",

            "impact":
            "Broad resource trust policy"

        })







    # object-src


    if "object-src" not in directives:


        result["security_analysis"]["missing_object_src"] = True


        result["risk_score"] += 5



        result["findings"].append({

            "issue":
            "object-src directive missing",

            "severity":
            "LOW",

            "impact":
            "Legacy plugin restrictions not explicitly defined"

        })








    domains = extract_domains(
        directives
    )



    result["third_party_domains"] = domains


    result["domain_count"] = len(
        domains
    )






    if len(domains) > 30:


        result["risk_score"] += 10



        result["findings"].append({

            "issue":
            "Large third-party trust boundary",

            "severity":
            "LOW",

            "impact":
            "Many external dependencies increase attack surface"

        })






    # Final risk


    if result["risk_score"] >= 50:


        result["risk_level"] = "HIGH"



    elif result["risk_score"] >= 25:


        result["risk_level"] = "MEDIUM"



    else:


        result["risk_level"] = "LOW"




    return result






if __name__ == "__main__":


    sample = """

    default-src 'self';

    script-src 'self' 'unsafe-inline' https://google.com;

    connect-src https://api.example.com;

    """



    output = analyze_csp(

        sample,

        "example.com"

    )


    print(output)