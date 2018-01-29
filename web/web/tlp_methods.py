from django.contrib.auth.models import User
from django.conf import settings
results_db = settings.MONGO


def get_tlp_users(user):
    l = []
    for g in user.groups.all():
        l.append(g.name)
    usersInGroup = User.objects.filter(groups__name__in=l)
    return [u.username for u in usersInGroup]


def get_analyses_numbers_matching_tlp(username, usersInGroup):
    query_object = get_mongo_tlp_query_object(username, usersInGroup)
    analyses = results_db.analysis.find(query_object, {"info.id": "1"})
    analyses_numbers = [str(result["info"]["id"]) for result in analyses]
    #print analyses_numbers
    #print query_object
    return analyses_numbers


def get_mongo_tlp_query_object(username, usersInGroup):
    query_object = {'$or': [{'$and': [{'info.tlp': 'red'}, {'info.owner': username}]},
                            {'$and': [{'info.tlp': 'amber'}, {'info.owner': {'$in': usersInGroup}}]},
                            {'info.tlp': 'green'}]}
    return query_object


def create_tlp_query(user, search_filter):
    return {
        "from": "0",
        "size": "10000",
        "sort":{"run_date":{"order":"desc"}},
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
