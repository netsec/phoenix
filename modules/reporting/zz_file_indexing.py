
import os
import codecs
import base64

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.core.database import Database, Task, Filepath


class FileIndexing(Report):
    def run(self, results):
        db = Database()
        paths = []
        root_path = self.analysis_path
        paths.extend(self.get_files('memory', root_path))
        paths.extend(self.get_files('buffer', root_path))
        paths.extend(self.get_files('files', root_path))

        session = db.Session()
        db_task = session.query(Task).filter(Task.id == self.task["id"]).one()
        db_task.filepaths = [Filepath(p, self.task["id"]) for p in paths]
        if "binary" in os.listdir(root_path):
            db_task.filepaths.append(Filepath("binary", self.task["id"]))
        session.add(db_task)
        session.commit()


    def get_files(self, slicepath, root_path):
        for root, directories, files in os.walk(os.path.join(root_path, slicepath), followlinks=True):
            for analysis_file in files:
                yield os.path.join(slicepath, analysis_file)
