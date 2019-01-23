from datetime import datetime
from django.contrib.auth.models import User
from django.conf import settings

from lib.cuckoo.core.database import Database

results_db = settings.MONGO


def get_tlp_users(user):
    l = []
    for g in user.groups.all():
        l.append(g.name)
    usersInGroup = User.objects.filter(groups__name__in=l)
    return list(set([u.username for u in usersInGroup] + [user.username]))


def get_analyses_numbers_matching_tlp(username, usersInGroup, start_datetime=None, stop_datetime=None):
    query_object = get_mongo_tlp_query_object(username, usersInGroup)
    print query_object
    full_query = [query_object]
    if start_datetime:
        full_query.append({"info.started": {"$gte": start_datetime, "$lte": stop_datetime}})
    if stop_datetime:
        full_query.append({"info.ended": {"$lte": stop_datetime}})
    analyses = list(results_db.analysis.find({"$and": full_query}, {"info.id": "1", "_id": 0}))
    analyses_numbers = [str(result["info"]["id"]) for result in analyses]
    # print analyses_numbers
    # print query_object
    return analyses_numbers


def get_analyses_numbers_matching_tlp2(username, start_datetime=datetime.min, stop_datetime=datetime.max):
    query_object = get_mysql_tlp_query_object(username, start_datetime,stop_datetime)
    # full_query = [query_object]
    # if start_datetime:
    #     full_query.append({"info.started": {"$gte": start_datetime, "$lte": stop_datetime}})
    # if stop_datetime:
    #     full_query.append({"info.ended": {"$lte": stop_datetime}})
    # analyses = list(results_db.analysis.find({"$and": full_query}, {"info.id": "1", "_id": 0}))
    # analyses_numbers = [str(result["info"]["id"]) for result in analyses]
    # print analyses_numbers
    # print query_object
    return query_object


def get_mongo_tlp_query_object(username, usersInGroup):
    query_object = {'$or': [{'$and': [{'info.tlp': 'red'}, {'info.owner': username}]},
                            {'$and': [{'info.tlp': 'amber'}, {'info.owner': {'$in': usersInGroup}}]},
                            {'info.tlp': 'green'}]}
    return query_object


def get_mysql_tlp_query_object(username,start_time=datetime.min, end_time=datetime.max):
    mysql_db = Database()
    return mysql_db.get_ids_for_tlp(username,start_time, end_time)



def create_tlp_query(user, search_filter):
    return {
        "from": "0",
        "size": "10000",
        "sort": {"run_date": {"order": "desc"}},
        "query": {
            "bool": {
                "must": [
                    search_filter,
                    {"bool": {
                        "should": [
                            {"bool": {
                                "must": [
                                    {"term": {"tlp": "green"}}
                                ]
                            }},
                            {"bool": {
                                "must": [
                                    {"term": {"tlp": "amber"}},
                                    {"terms": {"username.raw": get_tlp_users(user)}}
                                ]
                            }},
                            {"bool": {
                                "must": [
                                    {"term": {"tlp": "red"}},
                                    {"term": {"username.raw": user.username}}
                                ]
                            }}
                        ]
                    }
                    }
                ]

            }}
    }
