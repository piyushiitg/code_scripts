from database import Database

class Oracle(Database):
    def __init__(self, kwargs):
        super(Oracle, self).__init__(kwargs)
    
    def query_monitor(self, inputdata):
        return "Query Health Monitor"
        pass

