import requests
import ssl
import socket

from datetime import datetime
from urllib.parse import urlparse





# ==============================
# DNS
# ==============================

def resolve_subdomain(host):

    result = {

        "host": host,

        "A": [],

        "AAAA": []

    }


    try:

        answers = socket.gethostbyname_ex(
            host
        )

        result["A"] = answers[2]


    except Exception:

        pass



    try:

        infos = socket.getaddrinfo(
            host,
            None,
            socket.AF_INET6
        )


        result["AAAA"] = list(
            set(
                [
                    x[4][0]
                    for x in infos
                ]
            )
        )


    except Exception:

        pass



    return result





# ==============================
# SSL
# ==============================

def parse_cert_field(field):

    output={}


    for item in field:

        for key,value in item:

            output[key]=value


    return output





def get_ssl_info(host):


    result={

        "status":"FAILED"

    }



    try:


        context = ssl.create_default_context()



        with socket.create_connection(

            (host,443),

            timeout=5

        ) as sock:



            with context.wrap_socket(

                sock,

                server_hostname=host

            ) as ssock:



                cert=ssock.getpeercert()



                result={


                    "status":
                    "VALID",


                    "issuer":
                    parse_cert_field(
                        cert.get(
                            "issuer",
                            []
                        )
                    ),


                    "subject":
                    parse_cert_field(
                        cert.get(
                            "subject",
                            []
                        )
                    ),


                    "valid_from":
                    cert.get(
                        "notBefore"
                    ),


                    "valid_until":
                    cert.get(
                        "notAfter"
                    ),


                    "tls_version":
                    ssock.version()


                }




    except Exception as e:


        result={

            "status":"FAILED",

            "error":str(e)

        }



    return result







# ==============================
# Security Headers
# ==============================

SECURITY_HEADERS=[


    "strict-transport-security",

    "content-security-policy",

    "x-frame-options",

    "x-content-type-options",

    "referrer-policy",

    "permissions-policy"

]





def analyze_headers(headers):


    output={}


    lower={

        k.lower():v

        for k,v in headers.items()

    }


    for header in SECURITY_HEADERS:


        output[header]={

            "present":
            header in lower,


            "value":
            lower.get(header)

        }



    return output






# ==============================
# HTTP Intelligence
# ==============================

def get_http_info(host):


    result={


        "status_code":None,

        "url":None,

        "server":None,

        "powered_by":None,

        "technologies":[],


        "security_headers":{},


        "csp_raw":None,


        "cookies":[],


        "raw_headers":{}


    }




    try:


        response=requests.get(


            f"https://{host}",


            timeout=8,


            allow_redirects=True,


            headers={

                "User-Agent":
                "SentinelX-V2"

            }


        )



        headers=response.headers



        result["status_code"]=(
            response.status_code
        )


        result["url"]=(
            response.url
        )


        result["server"]=(
            headers.get(
                "Server"
            )
        )


        result["powered_by"]=(
            headers.get(
                "X-Powered-By"
            )
        )



        result["raw_headers"]=dict(
            headers
        )



        result["security_headers"]=(
            analyze_headers(
                headers
            )
        )



        result["csp_raw"]=(
            headers.get(
                "Content-Security-Policy"
            )
        )





        # Technology detection

        tech=[]


        header_string=str(
            headers
        ).lower()


        html=response.text.lower()



        fingerprints={


            "Cloudflare":
            "cloudflare",


            "Akamai":
            "akamai",


            "Nginx":
            "nginx",


            "Apache":
            "apache",


            "WordPress":
            "wordpress",


            "React":
            "react",


            "Next.js":
            "next.js"


        }




        for name,keyword in fingerprints.items():


            if keyword in header_string or keyword in html:


                tech.append(name)




        result["technologies"]=list(
            set(tech)
        )





        # Cookies


        cookies=[]


        for cookie in response.cookies:


            cookies.append({


                "name":
                cookie.name,


                "secure":
                cookie.secure,


                "httponly":
                "httponly"
                in str(cookie._rest).lower(),


                "samesite":
                cookie._rest.get(
                    "SameSite"
                )

            })



        result["cookies"]=cookies




        # WAF Detection

        if any(

            x in header_string

            for x in [

                "cloudflare",

                "akamai",

                "imperva",

                "sucuri"

            ]

        ):


            result["waf"]={


                "detected":True,


                "type":
                "Possible WAF/CDN"


            }


        else:


            result["waf"]={


                "detected":False

            }




    except Exception as e:


        result["error"]=str(e)




    return result







# ==============================
# Risk
# ==============================

def calculate_subdomain_risk(asset):


    score=0


    findings=[]


    host=asset["host"].lower()



    sensitive=[

        "admin",

        "dev",

        "test",

        "staging",

        "backup",

        "vpn",

        "internal",

        "old"

    ]



    for word in sensitive:


        if word in host:


            score+=10


            findings.append({


                "issue":
                f"Sensitive hostname keyword: {word}",


                "severity":
                "MEDIUM"


            })





    if asset["ssl"].get(
        "status"
    ) != "VALID":


        score+=20


        findings.append({


            "issue":
            "Invalid SSL certificate",


            "severity":
            "HIGH"


        })





    if asset["http"].get(
        "security_headers",
        {}
    ).get(
        "content-security-policy",
        {}
    ).get(
        "present"
    ) == False:


        score+=10


        findings.append({


            "issue":
            "Missing Content Security Policy",


            "severity":
            "LOW"


        })






    return {


        "score":score,


        "severity":

            "HIGH"
            if score>=40

            else

            "MEDIUM"
            if score>=20

            else

            "LOW",


        "findings":findings

    }







# ==============================
# Main Enrichment
# ==============================

def enrich_subdomain(host):


    asset={


        "host":host,


        "timestamp":
        datetime.utcnow().isoformat(),


        "dns":{},


        "ssl":{},


        "http":{},


        "risk":{}


    }




    print(
        "[+] DNS"
    )


    asset["dns"]=resolve_subdomain(
        host
    )



    print(
        "[+] SSL"
    )


    asset["ssl"]=get_ssl_info(
        host
    )



    print(
        "[+] HTTP Technology"
    )


    asset["http"]=get_http_info(
        host
    )



    print(
        "[+] Risk"
    )


    asset["risk"]=calculate_subdomain_risk(
        asset
    )



    return asset



def enrich_all_subdomains(subdomain_result):


    assets=[]


    for item in subdomain_result["subdomains"]:


        host=item["host"]


        try:

            print(
                f"\n========== {host} =========="
            )


            asset=enrich_subdomain(
                host
            )


            assets.append(asset)



        except Exception as e:


            assets.append({

                "host":host,

                "error":str(e)

            })



    return {


        "domain":
        subdomain_result["domain"],


        "timestamp":
        datetime.utcnow().isoformat(),


        "total_assets":
        len(assets),


        "assets":
        assets

    }



if __name__=="__main__":


    target=input(
        "Enter subdomain: "
    ).strip().lower()



    result=enrich_subdomain(
        target
    )



    print(result)