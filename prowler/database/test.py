from datetime import datetime

from gridfs import GridFS
# from pymongo.mongo_client import MongoClient
#
#
# uri = "mongodb+srv://tarunkumar:tarun@cluster.nopycic.mongodb.net/"
#
# client = MongoClient(uri)
# dbs= client.list_database_names()
# print(dbs)
# db = client.files
# collection_list = db.list_collection_names()
# print(collection_list)
# db = client.outputfiles
# record = db.compliance




from pymongo.mongo_client import MongoClient

uri = "mongodb+srv://tarunkumar:tarun@cluster.nopycic.mongodb.net/files"  # Include the database name in the connection string

try:
    client = MongoClient(uri)
    dbs = client.list_database_names()
    print("Databases:", dbs)

    db = client.files
    collection_list = db.list_collection_names()
    print("Collections in 'files' database:", collection_list)

except Exception as e:
    print("Error:", e)
