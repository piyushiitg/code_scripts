import MySQLdb

def get_connection(host, port, user, passwd, db='mysql', connect_timeout=5, ssl=None):

    params_dict = dict(host=host,
          connect_timeout=connect_timeout,
          port=port,
          user=user,
          passwd=passwd,
          db=db)
    if ssl:
        params_dict.update({'ssl':ssl})

    dbconn = MySQLdb.Connect(**params_dict)
    cursor = dbconn.cursor(MySQLdb.cursors.DictCursor)
    return dbconn, cursor



conn, cursor = get_connection("10.0.100.1", 3306, "root", "admin@123")
cursor.execute("select * from mysql.user")
res = cursor.fetchall()
print res
