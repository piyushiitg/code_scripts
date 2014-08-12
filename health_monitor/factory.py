from mysql import Mysql
from mssql import Mssql
from oracle import Oracle

class DatabaseFactory(object):

    def __new__(cls, kwargs):
        ''' Return database objects based on the
            Type of the database 
        '''
        if kwargs['db_type'] == 'MYSQL':
            return Mysql(kwargs)    
        if kwargs['db_type'] == 'MSSQL':
            return Mssql(kwargs)    
        if kwargs['db_type'] == 'ORACLE':
            return Oracle(kwargs) 
         









 
