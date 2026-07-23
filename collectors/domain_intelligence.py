import socket
import whois
import dns.resolver
import requests

from datetime import datetime

from ipwhois import IPWhois



# ==========================================
# WHOIS INTELLIGENCE
# ==========================================


def get_whois_info(domain):

    result={}

    try:

        data=whois.whois(domain)


        result={

            "registrar":
            data.registrar,


            "organization":
            data.org,


            "created":
            str(data.creation_date),


            "updated":
            str(data.updated_date),


            "expires":
            str(data.expiration_date),


            "status":
            data.status,


            "emails":
            data.emails

        }


    except Exception as e:


        result={

            "error":str(e)

        }


    return result






# ==========================================
# DNS REGISTRATION INTELLIGENCE
# ==========================================


def get_nameservers(domain):


    servers=[]


    try:


        answers=dns.resolver.resolve(

            domain,

            "NS"

        )


        for ns in answers:

            servers.append(
                str(ns)
                .rstrip(".")
            )


    except Exception:

        pass



    return servers





def check_dnssec(domain):


    try:


        dns.resolver.resolve(

            domain,

            "DNSKEY"

        )


        return True


    except Exception:


        return False






# ==========================================
# IP / ASN INTELLIGENCE
# ==========================================


def get_infrastructure(domain):


    result={


        "ip":None,

        "asn":None,

        "organization":None,

        "country":None,

        "reverse_dns":None


    }



    try:


        ip=socket.gethostbyname(domain)


        result["ip"]=ip



        try:


            result["reverse_dns"]=socket.gethostbyaddr(ip)[0]


        except Exception:

            pass





        obj=IPWhois(ip)


        data=obj.lookup_rdap()



        result["asn"]=data.get(
            "asn"
        )


        result["organization"]=data.get(
            "asn_description"
        )


        result["country"]=data.get(
            "asn_country_code"
        )



    except Exception as e:


        result["error"]=str(e)



    return result






# ==========================================
# TLD INTELLIGENCE
# ==========================================


def get_tld_info(domain):


    parts=domain.split(".")


    if len(parts)>=2:


        tld="."+parts[-1]


    else:

        tld=None



    return {


        "tld":tld,


        "length":
        len(domain),


        "subdomain":

        len(parts)>2


    }






# ==========================================
# DOMAIN REPUTATION
# ==========================================


def calculate_domain_reputation(profile):


    score=0

    findings=[]



    whois_data=profile.get(
        "whois",
        {}
    )



    if "error" in whois_data:


        score+=10


        findings.append(
            "WHOIS information unavailable"
        )





    created=whois_data.get(
        "created"
    )



    if created:


        try:


            year=int(
                created[-4:]
            )


            age=datetime.utcnow().year-year



            if age < 1:


                score+=20


                findings.append(
                    "Very new domain"
                )


        except Exception:

            pass





    tld=profile.get(
        "tld",
        {}
    ).get(
        "tld"
    )



    risky=[

        ".xyz",

        ".top",

        ".click",

        ".zip"

    ]



    if tld in risky:


        score+=10


        findings.append(

            "High risk TLD"

        )




    return {


        "score":score,


        "severity":

        "HIGH"
        if score>=30

        else

        "MEDIUM"
        if score>=15

        else

        "LOW",



        "findings":findings


    }








# ==========================================
# MAIN DOMAIN INTELLIGENCE
# ==========================================


def get_domain_info(domain):


    profile={


        "domain":domain,


        "timestamp":

        datetime.utcnow().isoformat()+"Z",



        "whois":{},


        "nameservers":[],


        "dnssec":False,


        "infrastructure":{},


        "tld":{},


        "reputation":{}


    }





    print("[+] WHOIS")


    profile["whois"]=get_whois_info(
        domain
    )





    print("[+] Nameservers")


    profile["nameservers"]=get_nameservers(
        domain
    )





    print("[+] DNSSEC")


    profile["dnssec"]=check_dnssec(
        domain
    )





    print("[+] Infrastructure")


    profile["infrastructure"]=get_infrastructure(
        domain
    )





    print("[+] TLD Intelligence")


    profile["tld"]=get_tld_info(
        domain
    )





    print("[+] Domain Reputation")


    profile["reputation"]=calculate_domain_reputation(
        profile
    )




    return profile






if __name__=="__main__":


    domain=input(
        "Enter domain: "
    )


    result=get_domain_info(
        domain
    )


    print("\n========== RESULT ==========")


    print(result)