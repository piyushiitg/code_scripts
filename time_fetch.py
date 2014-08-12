#from f import first
#from s import second
from t import third
n = third.split("\n")
l = len(n)
sqlite_time = 0
max_sqlite_time = 0 
min_sqlite_time = 10000 
sql_query_time = 0 
max_query_time = 0
min_query_time = 10000
resolv_chk_time = 0
max_resolv_chk_time = 0 
min_resolv_chk_time = 10000 
process_any_change = 0
max_process_any_change = 0
min_process_any_change = 1000000
write_to_sqlite_core = 0
max_write_to_sqlite_core = 0
min_write_to_sqlite_core = 10000
complete_time = 0
max_complete_time = 0
min_complete_time = 10000
connection_time = 0
max_connection_time = 0
min_connection_time = 10000
query1_time = 0
max_query1_time = 0
min_query1_time = 10000
query2_time = 0
max_query2_time = 0
min_query2_time = 10000  
query3_time = 0
max_query3_time = 0
min_query3_time = 10000
query4_time = 0
max_query4_time = 0
min_query4_time = 10000

x = []
for n1 in n:
    n1 = n1.strip()
    n2 = n1.split(",")
    if max_sqlite_time < float(n2[0].split(" ")[-1]):
        max_sqlite_time = float(n2[0].split(" ")[-1])
    if min_sqlite_time > float(n2[0].split(" ")[-1]):
        min_sqlite_time = float(n2[0].split(" ")[-1])
    sqlite_time += float(n2[0].split(" ")[-1])

    if max_query_time < float(n2[1].split(" ")[-1]):
        max_query_time = float(n2[1].split(" ")[-1])
    if min_query_time > float(n2[1].split(" ")[-1]):
        min_query_time = float(n2[1].split(" ")[-1])
    sql_query_time += float(n2[1].split(" ")[-1]) 

    if max_resolv_chk_time < float(n2[2].split(" ")[-1]):
       max_resolv_chk_time = float(n2[2].split(" ")[-1])
    if min_resolv_chk_time > float(n2[2].split(" ")[-1]):
       min_resolv_chk_time = float(n2[2].split(" ")[-1])
    resolv_chk_time += float(n2[2].split(" ")[-1]) 

    if max_process_any_change < float(n2[3].split(" ")[-1]):
        max_process_any_change = float(n2[3].split(" ")[-1])
    if min_process_any_change > float(n2[3].split(" ")[-1]):
        min_process_any_change = float(n2[3].split(" ")[-1])
    process_any_change += float(n2[3].split(" ")[-1])

    if max_write_to_sqlite_core < float(n2[4].split(" ")[-1]):
        max_write_to_sqlite_core = float(n2[4].split(" ")[-1])
    if min_write_to_sqlite_core > float(n2[4].split(" ")[-1]):
        min_write_to_sqlite_core = float(n2[4].split(" ")[-1])
    write_to_sqlite_core += float(n2[4].split(" ")[-1])

    if max_connection_time < float(n2[5].split(" ")[-1]):
        max_connection_time = float(n2[5].split(" ")[-1])
    if min_connection_time > float(n2[5].split(" ")[-1]):
        min_connection_time = float(n2[5].split(" ")[-1])
    connection_time += float(n2[5].split(" ")[-1])
   
    if max_query1_time < float(n2[6].split(" ")[-1]):
        max_query1_time = float(n2[6].split(" ")[-1])
    if min_query1_time > float(n2[6].split(" ")[-1]):
        min_query1_time = float(n2[6].split(" ")[-1])
    query1_time += float(n2[6].split(" ")[-1])

    if max_query2_time < float(n2[7].split(" ")[-1]):
        max_query2_time = float(n2[7].split(" ")[-1])
    if min_query2_time > float(n2[7].split(" ")[-1]):
        min_query2_time = float(n2[7].split(" ")[-1])
    query2_time += float(n2[7].split(" ")[-1])
  
    if max_query3_time < float(n2[8].split(" ")[-1]):
        max_query3_time = float(n2[8].split(" ")[-1])
    if min_query3_time > float(n2[8].split(" ")[-1]):
        min_query3_time = float(n2[8].split(" ")[-1])
    query3_time += float(n2[8].split(" ")[-1])
  
    if max_query4_time < float(n2[9].split(" ")[-1]):
        max_query4_time = float(n2[9].split(" ")[-1])
    if min_query4_time > float(n2[9].split(" ")[-1]):
        min_query4_time = float(n2[9].split(" ")[-1])
    query4_time += float(n2[9].split(" ")[-1])

    if max_complete_time < float(n2[10].split(" ")[-1]):
        max_complete_time = float(n2[10].split(" ")[-1])
    if min_complete_time > float(n2[10].split(" ")[-1]):
        min_complete_time = float(n2[10].split(" ")[-1])
    complete_time += float(n2[10].split(" ")[-1])

print "Parameter:        Min    Avg    Max    Total"
print "sqlite_time ",min_sqlite_time," ", sqlite_time/l, " ", max_sqlite_time," ",sqlite_time
print "sql_query_time ",min_query_time," ", sql_query_time/l," ", max_query_time," ",sql_query_time
print "resolv_chk_time ",min_resolv_chk_time," ", resolv_chk_time/l," ", max_resolv_chk_time," ",resolv_chk_time
print "process_any_change ",min_process_any_change," ", process_any_change/l," ", max_process_any_change," ",process_any_change
print "write_to_sqlite_core ",min_write_to_sqlite_core," ", write_to_sqlite_core/l," ", max_write_to_sqlite_core," ", write_to_sqlite_core
print "Connection_time ", min_connection_time, " ",connection_time/l," ",max_connection_time, " ",connection_time
print "Query1_time ", min_query1_time, " ", query1_time/l, " ", max_query1_time, " ", query1_time
print "Query2_time ", min_query2_time, " ", query2_time/l, " ", max_query2_time, " ", query2_time
print "Query3_time ", min_query3_time, " ", query3_time/l, " ", max_query3_time, " ", query3_time
print "Query4_time ", min_query4_time, " ", query4_time/l, " ", max_query4_time, " ", query4_time
print "complete_time ",min_complete_time," ", complete_time/l," ", max_complete_time," ",complete_time
print "no_of_cases ", l
