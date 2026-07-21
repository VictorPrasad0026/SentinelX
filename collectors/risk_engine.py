from datetime import datetime
from dateutil import parser



def add_finding(findings, issue, severity, recommendation=None):

    finding = {

        "issue": issue,

        "severity": severity

    }


    if recommendation:

        finding["recommendation"] = recommendation


    findings.append(finding)




def calculate_ssl_risk(ssl_data, findings):

    score = 0


    ssl = ssl_data.get(
        "ssl",
        {}
    )


    tls = ssl.get(
        "tls_version"
    )


    if tls == "TLSv1.3":

        pass


    elif tls == "TLSv1.2":

        score += 5

        add_finding(

            findings,

            "TLS 1.2 detected",

            "LOW",

            "Consider upgrading to TLS 1.3"

        )


    elif tls in [
        "TLSv1",
        "TLSv1.1"
    ]:

        score += 20

        add_finding(

            findings,

            "Deprecated TLS version detected",

            "HIGH",

            "Disable old TLS protocols"

        )


    # Certificate expiry

    expiry = ssl.get(
        "valid_until"
    )


    if expiry:

        try:

            expiry_date = parser.parse(
                expiry
            )

            remaining = (
                expiry_date -
                datetime.utcnow()
            ).days


            if remaining < 7:

                score += 40

                add_finding(

                    findings,

                    "SSL certificate expires soon",

                    "HIGH",

                    "Renew certificate immediately"

                )


            elif remaining < 30:

                score += 20

                add_finding(

                    findings,

                    "SSL certificate expiry approaching",

                    "MEDIUM",

                    "Plan certificate renewal"

                )


        except:

            pass



    return score





def calculate_header_risk(technology, findings):

    score = 0


    headers = technology.get(
        "security_headers",
        {}
    )


    checks = {


        "content-security-policy":
        (
            "Missing Content Security Policy",
            "MEDIUM",
            10
        ),


        "strict-transport-security":
        (
            "Missing HSTS Header",
            "MEDIUM",
            10
        ),


        "x-frame-options":
        (
            "Missing X-Frame-Options",
            "LOW",
            5
        ),


        "x-content-type-options":
        (
            "Missing X-Content-Type-Options",
            "LOW",
            5
        )

    }



    for header, data in checks.items():


        header_data = headers.get(
            header,
            {}
        )


        if not header_data.get(
            "present",
            False
        ):


            score += data[2]


            add_finding(

                findings,

                data[0],

                data[1],

                "Configure security header"

            )


    return score





def calculate_cookie_risk(technology, findings):

    score = 0


    cookies = technology.get(
        "cookies",
        []
    )


    for cookie in cookies:


        if not cookie.get(
            "secure"
        ):


            score += 5


            add_finding(

                findings,

                f"Cookie {cookie.get('name')} missing Secure flag",

                "LOW"

            )



        if not cookie.get(
            "httponly"
        ):


            score += 5


            add_finding(

                findings,

                f"Cookie {cookie.get('name')} missing HttpOnly flag",

                "LOW"

            )



    return score





def calculate_protection_score(technology, findings):


    score = 0


    protection = technology.get(
        "protection",
        {}
    )


    if protection.get(
        "detected"
    ):


        # small positive adjustment

        score -= 2


        add_finding(

            findings,

            "WAF/CDN protection detected",

            "INFO",

            "Edge protection reduces exposure but does not remove application risks"

        )


    return score





def calculate_risk(asset_profile):


    score = 0


    findings = []


    ssl_score = calculate_ssl_risk(

        asset_profile.get(
            "ssl_intelligence",
            {}
        ),

        findings

    )


    header_score = calculate_header_risk(

        asset_profile.get(
            "technology_intelligence",
            {}
        ),

        findings

    )


    cookie_score = calculate_cookie_risk(

        asset_profile.get(
            "technology_intelligence",
            {}
        ),

        findings

    )


    protection_score = calculate_protection_score(

        asset_profile.get(
            "technology_intelligence",
            {}
        ),

        findings

    )



    score = (

        ssl_score

        +

        header_score

        +

        cookie_score

        +

        protection_score

    )


    if score < 0:

        score = 0



    if score >= 70:

        severity = "CRITICAL"


    elif score >= 40:

        severity = "HIGH"


    elif score >= 20:

        severity = "MEDIUM"


    else:

        severity = "LOW"



    return {


        "timestamp":

        datetime.utcnow().isoformat(),


        "risk_score":

        score,


        "severity":

        severity,


        "findings":

        findings

    }