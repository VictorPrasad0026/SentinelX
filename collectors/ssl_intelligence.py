import ssl
import socket

from datetime import datetime



def parse_certificate_field(field):

    parsed = {}

    for item in field:

        for key, value in item:

            parsed[key] = value


    return parsed





def calculate_days_remaining(valid_until):

    try:

        expiry_date = datetime.strptime(
            valid_until,
            "%b %d %H:%M:%S %Y %Z"
        )


        today = datetime.utcnow()


        return (
            expiry_date - today
        ).days


    except:

        return None





def get_ssl_info(domain):


    result = {

        "domain": domain,

        "timestamp":
        datetime.utcnow().isoformat(),

        "ssl": {}

    }



    try:


        context = ssl.create_default_context()



        with socket.create_connection(
            (domain,443),
            timeout=5
        ) as sock:



            with context.wrap_socket(

                sock,

                server_hostname=domain

            ) as ssock:



                certificate = (
                    ssock.getpeercert()
                )



                issuer = parse_certificate_field(

                    certificate.get(
                        "issuer",
                        []
                    )

                )



                subject = parse_certificate_field(

                    certificate.get(
                        "subject",
                        []
                    )

                )



                valid_from = certificate.get(
                    "notBefore"
                )


                valid_until = certificate.get(
                    "notAfter"
                )



                tls_version = ssock.version()



                days_remaining = (
                    calculate_days_remaining(
                        valid_until
                    )
                )



                result["ssl"] = {


                    # Raw certificate evidence

                    "raw_certificate": certificate,



                    "issuer": issuer,


                    "subject": subject,



                    "valid_from":
                    valid_from,



                    "valid_until":
                    valid_until,



                    "days_remaining":
                    days_remaining,



                    "tls_version":
                    tls_version,



                    "security_checks": {


                        "tls_secure":
                        tls_version in [

                            "TLSv1.2",

                            "TLSv1.3"

                        ],



                        "certificate_valid":
                        True


                    },


                    "status":
                    "VALID"

                }





                # TLS risk information


                if tls_version in [

                    "TLSv1",

                    "TLSv1.1"

                ]:


                    result["ssl"]["security_checks"][

                        "tls_warning"

                    ] = (

                        "Weak TLS version detected"

                    )





    except ssl.CertificateError as e:


        result["ssl"] = {

            "status":
            "INVALID_CERTIFICATE",

            "error":
            str(e)

        }




    except Exception as e:


        result["ssl"] = {

            "status":
            "FAILED",

            "error":
            str(e)

        }




    return result





# Terminal testing

if __name__ == "__main__":


    target = input(
        "Enter domain: "
    )


    data = get_ssl_info(
        target
    )


    print(data)