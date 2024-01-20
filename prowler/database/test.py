# pip install pymongo

# import gridfs

from pymongo import MongoClient

from envi import  PASSWORD

URL = f"mongodb+srv://basapathitarunkumar9686:{PASSWORD}@cluster0.xljjfu2.mongodb.net/?retryWrites=true&w=majority"


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
#     file_name = "mnist_test.csv"
#     file_loc = "/content/sample_data/" + file_name
#
#     db = mongo_conn()
#     fs = gridfs.GridFS(db, collection="youtube")
#
#     # upload file
#     upload_file(file_loc=file_loc, file_name=file_name, fs=fs)