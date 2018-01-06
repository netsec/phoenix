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
    query_object = {'$or': [{'$and': [{'info.tlp': 'red'}, {'info.owner': username}]},
                            {'$and': [{'info.tlp': 'amber'}, {'info.owner': {'$in': usersInGroup}}]},
                            {'info.tlp': 'green'}]}
    analyses = results_db.analysis.find(query_object, {"info.id": "1"})
    analyses_numbers = [str(result["info"]["id"]) for result in analyses]
    return analyses_numbers


def create_tlp_query(user, search_filter):
    return {
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
                                    {"terms": {"username": get_tlp_users(user)}}
                                ]
                            }},
                            {"bool": {
                                "must": [
                                    {"term": {"tlp": "red"}},
                                    {"term": {"username": user.username}}
                                ]
                            }}
                        ]
                    }
                    }
                ]

            }}
    }
