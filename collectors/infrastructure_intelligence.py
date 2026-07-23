
"""
SentinelX Infrastructure Intelligence Engine v1.0

Collects:

- IP Intelligence
- ASN Information
- Geo Location
- Cloud Provider
- Reverse DNS
- CDN Detection
- Open Ports
- Service Fingerprinting
- Exposure Risk Score

Author:
SentinelX ASM Platform
"""


import socket
import subprocess
import json
from datetime import datetime


# ==========================================
# IP RESOLUTION
# ==========================================

def resolve_ip(domain):

    try:

        return socket.gethostbyname(domain)

    except Exception:

        return None




# ==========================================
# ASN INTELLIGENCE
# ==========================================

def get_asn_info(ip):


    try:

        # Placeholder ASN enrichment
        # Future:
        # MaxMind ASN DB
        # RIPE API
        # BGPView API


        known_clouds = {


            "3.": {

                "asn":"16509",
                "description":
                "AMAZON-02 - Amazon.com, Inc., US",
                "network":
                "AMAZON-AWS"

            },


            "13.": {

                "asn":"16509",
                "description":
                "AMAZON AWS",
                "network":
                "AWS"

            }

        }



        for prefix,data in known_clouds.items():

            if ip.startswith(prefix):

                return data



        return {


            "asn":
            "UNKNOWN",

            "asn_description":
            "Unknown",

            "network":
            "Unknown"

        }



    except Exception:


        return {

            "asn":"UNKNOWN"

        }




# ==========================================
# GEO IP
# ==========================================

def get_geoip(ip):


    """
    Enterprise version:

    Integrate:
    - MaxMind GeoLite2
    - IPinfo
    - DB-IP

    """

    return {


        "country":None,

        "city":None,

        "latitude":None,

        "longitude":None


    }




# ==========================================
# CLOUD DETECTION
# ==========================================

def detect_cloud(ip, reverse_dns):


    text = (

        str(ip)
        +
        str(reverse_dns)

    ).lower()



    if "amazonaws" in text or ip.startswith("3.") or ip.startswith("13."):

        return "AWS"



    if "azure" in text:

        return "Azure"



    if "google" in text:

        return "Google Cloud"



    return "Unknown"





# ==========================================
# REVERSE DNS
# ==========================================

def reverse_dns_lookup(ip):


    try:

        return socket.gethostbyaddr(ip)[0]


    except Exception:


        return None





# ==========================================
# CDN DETECTION
# ==========================================

def detect_cdn(domain):


    """
    Future integrations:

    Cloudflare
    Akamai
    Fastly
    CloudFront
    Imperva

    """


    try:


        result = socket.gethostbyname_ex(domain)


        cname = str(result).lower()



        cdns = {


            "cloudflare":
            "Cloudflare",


            "cloudfront":
            "AWS CloudFront",


            "akamai":
            "Akamai",


            "fastly":
            "Fastly"


        }



        for key,value in cdns.items():


            if key in cname:


                return {


                    "detected":True,

                    "provider":value

                }



    except Exception:

        pass



    return {


        "detected":False,

        "provider":None

    }







# ==========================================
# PORT SCANNER
# ==========================================

COMMON_PORTS = {


    21:"FTP",

    22:"SSH",

    25:"SMTP",

    53:"DNS",

    80:"HTTP",

    110:"POP3",

    143:"IMAP",

    443:"HTTPS",

    3306:"MYSQL",

    3389:"RDP",

    8080:"HTTP-ALT"


}





def scan_ports(ip):


    results=[]



    for port,service in COMMON_PORTS.items():


        try:


            sock=socket.socket(

                socket.AF_INET,

                socket.SOCK_STREAM

            )


            sock.settimeout(0.5)



            result=sock.connect_ex(

                (
                    ip,
                    port
                )

            )


            sock.close()



            if result==0:


                results.append({

                    "port":port,

                    "service":service,

                    "state":"OPEN"

                })


        except Exception:


            pass



    return results








# ==========================================
# SERVICE BANNER
# ==========================================

def get_service_banner(ip,port):


    try:


        sock=socket.socket()

        sock.settimeout(2)


        sock.connect(

            (
                ip,
                port
            )

        )


        banner=sock.recv(1024)


        sock.close()



        return banner.decode(

            errors="ignore"

        ).strip()



    except Exception:


        return None








# ==========================================
# EXPOSURE SCORE
# ==========================================

def calculate_exposure(open_ports, cloud):


    score=0



    for item in open_ports:


        port=item["port"]



        if port in [21,22,3389]:

            score+=10


        elif port in [80,443]:

            score+=5



    if cloud!="Unknown":

        score+=5



    return min(score,100)







# ==========================================
# MAIN ENGINE
# ==========================================

def get_infrastructure_info(domain):


    print("[+] Infrastructure Intelligence")



    result={


        "domain":domain,


        "timestamp":

        datetime.utcnow().isoformat()+"Z",


        "ip":None,


        "asn":{},


        "geoip":{},


        "cloud_provider":None,


        "reverse_dns":None,


        "cdn":{},


        "open_ports":[],


        "service_banners":[],


        "exposure_score":0


    }



    ip=resolve_ip(domain)



    if not ip:


        result["error"]="IP resolution failed"

        return result



    result["ip"]=ip



    result["asn"]=get_asn_info(ip)



    result["geoip"]=get_geoip(ip)



    result["reverse_dns"]=reverse_dns_lookup(ip)



    result["cloud_provider"]=detect_cloud(

        ip,

        result["reverse_dns"]

    )



    result["cdn"]=detect_cdn(domain)



    ports=scan_ports(ip)



    result["open_ports"]=ports




    for port in ports:


        banner=get_service_banner(

            ip,

            port["port"]

        )


        if banner:


            result["service_banners"].append({

                "port":port["port"],

                "banner":banner

            })




    result["exposure_score"]=calculate_exposure(

        ports,

        result["cloud_provider"]

    )



    return result







# ==========================================
# TEST
# ==========================================


if __name__=="__main__":


    domain=input(

        "Domain: "

    ).strip()



    data=get_infrastructure_info(

        domain

    )



    print(

        json.dumps(

            data,

            indent=4

        )

    )
