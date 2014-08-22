

database_configuration = { 
                        'ORACLE' : {
                                    'db_type' : 'ORACLE', 
                                    'socket_timeout' : 1,
                                    'query_timeout' : 1,
                                    'no_of_probe' : 3,
                                    'socket_retry' : 3,
                                    'query_retry' : 3,
                                    'query': {'default': "select 1", 'custom': '', 'dbdefault':''},
                                    'function' : ['socket'],
                                    'database' : ''
                                    },
                        'MYSQL' : {
                                    'db_type' : 'MYSQL', 
                                    'socket_timeout' : 1,
                                    'query_timeout' : 1,
                                    'no_of_probe' : 3,
                                    'socket_retry' : 3,
                                    'query_retry' : 3,
                                    'query': {'default': "select 1", 'custom': '', 'dbdefault':''},
                                    'function' : ['socket'],
                                    'database' : '',
                                    },
                        'MSSQL' : {
                                    'db_type' : 'MSSQL', 
                                    'socket_timeout' : 1,
                                    'query_timeout' : 1,
                                    'no_of_probe' : 3,
                                    'socket_retry' : 1,
                                    'query_retry' : 3,
                                    'query': {'default': "select 1", 'custom': '', 'dbdefault':''},
                                    'function' : ['socket'],
                                    'database' : '',
                                    },
                       }



