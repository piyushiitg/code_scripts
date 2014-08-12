import sqlite3

class SqliteHandler(object):

    def get_sqlite_data(self, db_name, query):
        db_handle = self.get_sqlite_handle(db_name)
        cursor = db_handle.cursor()
        result = None
        try:
            cursor.execute(query)
            result = cursor.fetchall()
        except Exception, ex:
            print "Exception in reading data cursor", ex
        finally:
            if cursor:
                cursor.close()
            if db_handle:
                db_handle.close()
        return result

    def get_sqlite_handle(self, db_name, timeout=None):
        '''
        Returns a sqlite handle to the recieved db_name
        '''
        try:
            if timeout:
                conn = sqlite3.connect(db_name, timeout=timeout)
            else:
                conn = sqlite3.connect(db_name)
            # obtain all results as python dictionaries
            conn.row_factory = sqlite3.Row
            return conn
        except :
            return None

    def read_all_config_data(self):
        #self.get_sqlite_data()
        pass
