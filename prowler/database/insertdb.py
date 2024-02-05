# pip install pymongo

import gridfs

from pymongo import MongoClient

# from envi import  PASSWORD

URL = f"mongodb+srv://basapathitarunkumar9686:12345@cluster.ssqkh2h.mongodb.net/?retryWrites=true&w=majority"


def mongo_conn():
    """create a connection"""
    try:
        conn = MongoClient(URL)
        print("Mongodb Connected", conn)
        return conn.compliance
    except Exception as err:
        print(f"Error in mongodb connection: {err}")


def upload_file(file_loc, file_name, fs):
    """upload file to mongodb"""
    with open(file_loc, 'rb') as file_data:
        data = file_data.read()

    # put file into mongodb
    fs.put(data, filename=file_name)
    print("Upload Complete")


# if __name__ == '__main__':
#     file_name = "prowler-output-906113748440-20240205113237_cis_1.4_aws"
#     file_loc = "prowler-output-906113748440-20240205113237_cis_1.4_aws.csv"
#
#     db = mongo_conn()
#     fs = gridfs.GridFS(db, collection="output1")
#
#     # upload file
#     upload_file(file_loc=file_loc, file_name=file_name, fs=fs)