from pymongo import MongoClient
from datetime import datetime



MONGO_URI = "mongodb://localhost:27017/"



client = MongoClient(
    MONGO_URI
)


db = client[
    "sentinelx"
]


assets_collection = db[
    "assets"
]


scans_collection = db[
    "scans"
]


findings_collection = db[
    "findings"
]




def save_scan(scan_data):


    scan_data["stored_at"] = (
        datetime.utcnow()
        .isoformat()
    )


    scans_collection.insert_one(
        scan_data
    )


    return True



def save_asset(domain):


    assets_collection.update_one(

        {
            "domain":domain
        },

        {
            "$set":{

                "domain":domain,

                "last_seen":
                datetime.utcnow()

            }

        },

        upsert=True

    )