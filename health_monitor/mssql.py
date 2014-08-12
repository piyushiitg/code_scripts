from database import Database
from sqlite import SqliteHandler
class Mssql(Database):
    def __init__(self, kwargs):
        super(Mssql, self).__init__(kwargs)

    def query_monitor(self, inputdata):
        return "MSSQL query Monitor"
         
