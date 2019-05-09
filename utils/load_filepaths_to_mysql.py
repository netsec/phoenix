import MySQLdb
import os
import logging

# logging.basicConfig()
logging.getLogger().setLevel(logging.INFO)
mysql_host = '172.18.1.252'
db = MySQLdb.connect(host=mysql_host,
                     user='root',
                     passwd='Root123',
                     db="cuckoo")
cur = db.cursor()
analyses = "/opt/phoenix/storage/analyses"
for analysis_number in os.listdir(analyses):
    if str.isdigit(analysis_number):
        logging.info("processing {0}".format(analysis_number))
        analyses_folder = os.path.join(analyses, analysis_number)
        for subdirectory in os.listdir(analyses_folder):
            if subdirectory in ["network", "buffer", "memory", "files"]:
                for filename in os.listdir(os.path.join(analyses_folder, subdirectory)):
                    filepath = os.path.join(subdirectory, filename)
                    logging.info("adding {0} to {1}".format(filepath, analysis_number))
                    cur.execute('insert ignore into filepaths values("{0}","{1}")'.format(analysis_number, filepath))
            if subdirectory == "binary":
                logging.info("Adding binary to {0}".format(analysis_number))
                cur.execute('insert ignore into filepaths values("{0}", "{1}")'.format(analysis_number, "binary"))
    db.commit()
db.close()
