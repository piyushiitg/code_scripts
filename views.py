import sys, time, os
import logging

from datetime import datetime, timedelta
from copy import deepcopy

from django.shortcuts import render
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from common.models import LbClustersSummary
from common.serializers import LbClustersSummarySerializer
import common.cluster_stats_serializers as cls_stats
import common.cluster_stats_models as stats_model
from restapi.settings import DATABASES
from common.lib import get_model, get_time_before_seconds, get_current_time

from mssql import models as mssql_models
from mysql import models as mysql_models
from oracle import models as oracle_models

from mssql import serializers as mssql_serializer
from mysql import serializers as mysql_serializer
from oracle import serializers as oracle_serializer

import common.stats_serializers as global_stats_serializer
import common.stats_models as global_stats_model

from datetime import datetime, timedelta
import auth_check
import copy

SYSTEM_FORMAT_STRUCTURE = {
         'connections':{
            'connections-client': 'client',
            'connections-server': 'server',
            'connections-read-queue':'readqueue',
            'connections-write-queue': 'writequeue',
            'connections-persistent': 'pclient',
            #'connections-readintentqueue': 'readintentqueue',
            #'connections-totalqueue': 'queue',
            'connections-passthrough_conn': 'passthrough_conn',
            'connections-error': 'connerror',
        },
         'cache':{
            #'cache-invalidation': 'invalidation_cachesize',
            'cache-hit':'cachehit',
            #'cache-hit-per': 'cache-hit-per',
            #'cache-size': 'cachesize',
            #'reads-from-cache': 'reads-from-cache',
            #'cache-vs-total': 'cache-vs-total',
        }, 
         'queries':{
            'queries-read':'read',
            'queries-write':'write',
            'queries-block':'block',    
            'queries-error':'queryerror',
            'queries-passthrough':'passthrough',
            #'queries-invalidation':'invalidation_counter',
        },
         'cpuusage':{
            'cpu-lb':'lb_cpu',
            'cpu-cache':'cache_cpu',
            'cpu-query':'query_cpu',
            'cpu-connection':'conn_cpu',
         },
         'bandwidthusage':{
            'bandwidth-in':'eth0_in',
            'bandwidth-out':'eth0_out',
         },

     }
 
log = logging.getLogger(__name__)

class ClusterList(APIView):
    """
        List all clusers, or create a new cluster.
    """

    @auth_check.scalearc_login_required
    def get(self, request, format=None):
        log.info("In Cluster API Get Call")
        clusters_info = [] 
        clusters_summary = LbClustersSummary.objects.filter(status__in=[1])
        for cluster in clusters_summary:
            db_name, model_type, serializer_type = get_model(cluster.cluster_id, cluster.type)

            tmp_info = model_type.LbClusters.objects.using(db_name).get()
            serializer = serializer_type.LbClustersSerializer(tmp_info)

            servers_info = model_type.LbServers.objects.using(db_name).all()
            servers = serializer_type.LbServersSerializer(servers_info, many=True)

            serializer.data.update(dict(iDB_type=cluster.type,
                                    cluster_servers=servers.data))
            clusters_info.append(serializer.data)
            response = {'success': True, 'message': '4077 Information for clusters',
                    'timestamp': time.time(), 'data': clusters_info}
        return Response(response)


class ClusterCounters(APIView):
    
    @auth_check.scalearc_login_required
    def get(self, request, format=None):
        response = {}
        clusters_counters = {}
        try:
            log.info("Get Cluster Counters")
            limit = int(request.GET.get('limit', 1))
            cluster_ids = request.GET.get('cids', [])
            
            cluster_ids = eval(cluster_ids) if cluster_ids else []
            
            log.debug("Input params limit %s and cluster Ids %s" % (limit, cluster_ids))
            clusters_counters = _get_clusters_counters(cluster_ids, limit)
            response['success'] = True
            message = 'Clusters counters'
        except Exception, ex:
            log.error('Error occurred in get clusters counter %s' % ex)
            response['success'] = False
            message = '%s' % ex
        finally:
            response['message'] = message
            response['data'] = clusters_counters
            return Response(response)

def _get_clusters_counters(cluster_ids=[], limit=1):
    clusters_counters = {}

    filter_query = dict(status__in=[1])
    if cluster_ids:
        filter_query.update(cluster_id__in=cluster_ids)

    clustes_summary = LbClustersSummary.objects.filter(**filter_query)
    for cluster in clustes_summary:
        lb_db_name, model, serializer = get_model(cluster.cluster_id, cluster.type)
        stats_db_name = 'lbstats_%s' % cluster.cluster_id
        clusters_counters[cluster.cluster_id] = _get_counters(lb_db_name,
                                                                stats_db_name,
                                                                model,
                                                                serializer,
                                                                cluster.cluster_id,
                                                                limit)
    return clusters_counters


def _get_counters(lb_db_name, stats_db_name, model, serializer, cid, limit):
    
    current_time = get_current_time() - timedelta(seconds=5)
    old_time = (current_time - timedelta(seconds=limit-1)).strftime("%Y-%m-%d %H:%M:%S")
    current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    log.info("In Cluster Counters: Current Time %s, Old Time %s" % (current_time, old_time))

    connections_data_list = cls_stats.LbCconnectionsSerializer(\
                                stats_model.LbCconnections.objects.using(stats_db_name)\
                                    .filter(updatetime__gte=old_time, 
                                            updatetime__lte=current_time), many=True)

    servers_data = _get_servers(lb_db_name, model, serializer)

    servers_stats = cls_stats.LbSrvstatsSerializer(stats_model.LbSrvstats.objects.using(stats_db_name)\
                        .filter(updatetime__gte=old_time,
                                updatetime__lte=current_time), many=True)

    dbs_stats = cls_stats.LbDbstatsSerializer(stats_model.LbDbstats.objects.using(stats_db_name)\
                                .filter(updatetime__gte=old_time,
                                        updatetime__lte=current_time), many=True)

    counters_list = _do_formating(connections_data_list, servers_data, 
                                    servers_stats, dbs_stats)
    return counters_list

FORMAT_STRUCTURE = {
        'connections':{
            'connections-client': 'client',
            'connections-server': 'server',
            'connections-read-queue':'readqueue',
            'connections-write-queue': 'writequeue',
            'connections-persistent': 'pclient',
            'connections-readintentqueue': 'readintentqueue',
            'connections-totalqueue': 'queue',
            'connections-passthrough_conn': 'passthrough_conn',
            'connections-error': 'connerror',
        },
        'queries':{
            'queries-read':'read',
            'queries-write':'write',
            'queries-block':'block',
            'queries-error':'queryerror',
            'queries-passthrough':'passthrough',
            'queries-invalidation':'invalidation_counter',
        },
        'cache':{
            'cache-invalidation': 'invalidation_cachesize',
            'cache-hit':'cachehit',
            'cache-hit-per': 'cache-hit-per',
            'cache-size': 'cachesize',
            'reads-from-cache': 'reads-from-cache',
            'cache-vs-total': 'cache-vs-total',
        },
}

def _do_formating(connections_data_list, servers_data, 
                    servers_stats, dbs_stats):

    counters_list = []
    for connection_data in connections_data_list.data:
        cluster_counter_format = deepcopy(FORMAT_STRUCTURE)
        updatetime = connection_data.get('updatetime')

        for category, c_values in cluster_counter_format.iteritems():
            for field, sqlite_name in c_values.iteritems():
                cluster_counter_format[category][field] = connection_data.get(sqlite_name, 0)

        cluster_counter_format['servers'] = []
        for server in servers_stats.data:
            server_id = server.get('serverid')
            stat = {}
            if updatetime == server.get('updatetime') and server_id in servers_data:
                server_ip = servers_data[server_id].replace('.', "_")
                stat['server-%s' % server_ip] = server.get('readsize', 0) + server.get('writesize', 0)
                stat['server-replicationlag-%s' % server_ip] = server.get('replicationlag', 0)
                cluster_counter_format['servers'].append(stat)

        cluster_counter_format['dbcache'] = []
        for database in dbs_stats.data:
            stat = {}
            if updatetime == database.get('updatetime'):
                stat['dbcache-%s' % database.get('dbid')] = round(database.get('cachesize', 0.0)/1048576.0, 2)
                cluster_counter_format['dbcache'].append(stat)

        cluster_counter_format['time'] = updatetime.strftime("%Y-%m-%d %H:%M:%S")
        counters_list.append(cluster_counter_format)

    return counters_list

def _get_servers(db_name, model, serializer):
    servers_data = {}
    for server in model.LbServers.objects.using(db_name).filter(status__in=[1]):
       servers_data[server.serverid] = server.ipaddress
    return servers_data

def create_system_counter_formatting(lbcconnection_system_stats, lbscpu_system_stats):
    ''' Format System Monitor Counter
    '''
    connection_data = {}
   
    #print "---------->", lbcconnection_system_stats
    print "----------------", lbscpu_system_stats 
    for data in lbcconnection_system_stats:
        updatetime = data.get("updatetime").strftime("%Y-%m-%d %H:%M:%S")
        connection_data[updatetime] = data 

    for scpu_data in lbscpu_system_stats:
        updatetime = scpu_data.get("updatetime").strftime("%Y-%m-%d %H:%M:%S")
        conn_data = connection_data.get(updatetime)
        if conn_data:
            conn_data.update(scpu_data)

    output_data = []
    for updatetime, sqlite_data in connection_data.iteritems():
        print "******************", updatetime, sqlite_data
        format_structure = copy.deepcopy(SYSTEM_FORMAT_STRUCTURE)
        for key, values in format_structure.iteritems():
            for api_name, sqlite_name in values.iteritems():
                format_structure[key][api_name] = sqlite_data.get(sqlite_name, 0)
        format_structure.update({'time': updatetime})
        output_data.append(format_structure)
    return output_data
 
class SystemCounters(APIView):
    '''
    '''
    def get(self, request):
        response = {}
        limit = 1
        current_time = get_current_time() - timedelta(seconds=5)
        old_time = (current_time - timedelta(seconds=limit)).strftime("%Y-%m-%d %H:%M:%S")
 
        current_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
        lbcconnection_stats_data = global_stats_serializer.LbCconnectionsSerializer(global_stats_model.LbCconnections1.objects.using("lbstats").filter(updatetime__gte=old_time, updatetime__lte=current_time), many=True)
        lbscpu_stats_data = global_stats_serializer.LbScpuSerializer(global_stats_model.LbScpu1.objects.using("lbstats").filter(updatetime__gte=old_time, updatetime__lte=current_time), many=True)
        output_data = create_system_counter_formatting(lbcconnection_stats_data.data, lbscpu_stats_data.data)
        response['success'] = True
        message = 'System counters'
        response['message'] = message
        response['data'] = output_data
        return Response(response)
 
