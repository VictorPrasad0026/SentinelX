import dns.resolver
import socket

from datetime import datetime



# ==========================================
# DNS HELPER
# ==========================================

def query_dns(name, record_type):

    try:

        answers = dns.resolver.resolve(
            name,
            record_type,
            lifetime=5
        )

        return [

            str(record).replace('"','')

            for record in answers

        ]


    except Exception:

        return []





# ==========================================
# MX INTELLIGENCE
# ==========================================

def analyze_mx(domain):


    result={

        "records":[],
        "provider":"Unknown"

    }


    mx_records=query_dns(
        domain,
        "MX"
    )


    for record in mx_records:


        parts=record.split()


        if len(parts)>=2:


            result["records"].append({

                "priority":parts[0],

                "host":parts[1].rstrip(".")

            })



    data=" ".join(mx_records).lower()



    providers={


        "Google Workspace":[

            "google.com",

            "googlemail.com"

        ],


        "Microsoft 365":[

            "outlook.com",

            "protection.outlook.com"

        ],


        "Zoho":[

            "zoho.com"

        ],


        "Amazon SES":[

            "amazonses.com"

        ],


        "Proton Mail":[

            "protonmail"

        ]

    }



    for provider,keywords in providers.items():


        for keyword in keywords:


            if keyword in data:

                result["provider"]=provider



    return result





# ==========================================
# SPF INTELLIGENCE
# ==========================================


def analyze_spf(domain):


    result={


        "enabled":False,


        "record":None,


        "mechanisms":[],


        "includes":[],


        "policy":"UNKNOWN",


        "risk":"HIGH"

    }



    records=query_dns(

        domain,

        "TXT"

    )



    for record in records:


        if record.lower().startswith(

            "v=spf1"

        ):


            result["enabled"]=True


            result["record"]=record



            parts=record.split()



            for item in parts[1:]:


                if item.startswith(

                    "include:"

                ):


                    result["includes"].append(

                        item.replace(
                            "include:",
                            ""
                        )

                    )


                else:


                    result["mechanisms"].append(

                        item

                    )




                if item=="-all":


                    result["policy"]="hardfail"

                    result["risk"]="LOW"



                elif item=="~all":


                    result["policy"]="softfail"

                    result["risk"]="MEDIUM"



                elif item=="+all":


                    result["policy"]="allow_all"

                    result["risk"]="CRITICAL"



            break



    return result





# ==========================================
# DMARC INTELLIGENCE
# ==========================================


def analyze_dmarc(domain):


    result={


        "enabled":False,


        "record":None,


        "policy":"NONE",


        "rua":[],


        "ruf":[],


        "alignment":{},


        "risk":"HIGH"

    }




    records=query_dns(

        "_dmarc."+domain,

        "TXT"

    )



    for record in records:


        if "v=dmarc1" in record.lower():


            result["enabled"]=True


            result["record"]=record



            values={}



            for item in record.split(";"):


                item=item.strip()


                if "=" in item:


                    key,value=item.split(

                        "=",

                        1

                    )


                    values[key.lower()]=value




            result["policy"]=values.get(

                "p",

                "none"

            )



            if "rua" in values:


                result["rua"]=values["rua"].split(",")



            if "ruf" in values:


                result["ruf"]=values["ruf"].split(",")




            result["alignment"]={


                "dkim":

                values.get(

                    "adkim",

                    "relaxed"

                ),


                "spf":

                values.get(

                    "aspf",

                    "relaxed"

                )

            }



            if result["policy"]=="reject":


                result["risk"]="LOW"



            elif result["policy"]=="quarantine":


                result["risk"]="MEDIUM"



            elif result["policy"]=="none":


                result["risk"]="HIGH"



            break



    return result





# ==========================================
# DKIM DISCOVERY
# ==========================================


COMMON_SELECTORS=[


    "default",

    "google",

    "selector1",

    "selector2",

    "mail",

    "smtp",

    "dkim"

]



def analyze_dkim(domain):


    result={


        "status":

        "NOT_FOUND",


        "confidence":

        "LOW",


        "selectors_tested":

        COMMON_SELECTORS,


        "found_selectors":[]

    }




    for selector in COMMON_SELECTORS:


        query=(

            selector

            +

            "._domainkey."

            +

            domain

        )


        records=query_dns(

            query,

            "TXT"

        )



        if records:


            result["found_selectors"].append(

                selector

            )



    if result["found_selectors"]:


        result["status"]="FOUND"

        result["confidence"]="HIGH"



    return result





# ==========================================
# SMTP FOUNDATION
# ==========================================


def analyze_smtp(mx_data):


    result={


        "servers":[],


        "tls_supported":None,


        "open_relay":None

    }



    for item in mx_data.get(

        "records",

        []

    ):


        host=item["host"]


        try:


            ip=socket.gethostbyname(

                host

            )


            result["servers"].append({

                "host":host,

                "ip":ip

            })


        except Exception:


            pass



    return result





# ==========================================
# EMAIL RISK ENGINE
# ==========================================


def calculate_email_risk(email):


    score=0


    findings=[]



    spf=email["spf"]


    dmarc=email["dmarc"]


    dkim=email["dkim"]



    if not spf["enabled"]:


        score+=15


        findings.append({

            "issue":
            "Missing SPF",

            "severity":
            "HIGH"

        })



    elif spf["risk"]=="CRITICAL":


        score+=25


        findings.append({

            "issue":
            "SPF allows all senders",

            "severity":
            "CRITICAL"

        })




    if not dmarc["enabled"]:


        score+=15


        findings.append({

            "issue":
            "Missing DMARC",

            "severity":
            "HIGH"

        })



    elif dmarc["policy"]=="none":


        score+=10


        findings.append({

            "issue":
            "DMARC policy monitoring only",

            "severity":
            "MEDIUM"

        })




    if dkim["status"]!="FOUND":


        score+=8


        findings.append({

            "issue":
            "DKIM selector not discovered",

            "severity":
            "MEDIUM"

        })




    return {


        "score":score,


        "findings":findings


    }





# ==========================================
# MAIN COLLECTOR
# ==========================================


def get_email_intelligence(domain):


    result={


        "domain":domain,


        "timestamp":

        datetime.utcnow().isoformat()+"Z",



        "mx":{},


        "spf":{},


        "dmarc":{},


        "dkim":{},


        "smtp":{},


        "risk":{}

    }




    print("[+] MX Intelligence")


    result["mx"]=analyze_mx(

        domain

    )



    print("[+] SPF Intelligence")


    result["spf"]=analyze_spf(

        domain

    )



    print("[+] DMARC Intelligence")


    result["dmarc"]=analyze_dmarc(

        domain

    )



    print("[+] DKIM Discovery")


    result["dkim"]=analyze_dkim(

        domain

    )



    print("[+] SMTP Mapping")


    result["smtp"]=analyze_smtp(

        result["mx"]

    )



    print("[+] Email Risk")


    result["risk"]=calculate_email_risk(

        result

    )



    return result





if __name__=="__main__":


    target=input(

        "Enter domain: "

    ).strip()



    output=get_email_intelligence(

        target

    )


    print(output)