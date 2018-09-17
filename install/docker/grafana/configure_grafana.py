import json
import os
import sys
from grafana_api_client import GrafanaClient
grafana_host= sys.argv[1]
elastic_host = sys.argv[2]
admin_client = GrafanaClient("eyJrIjoiY21sM1JRYjB6RnVYSTNLenRWQkFEaWN1bXI2V202U3IiLCJuIjoiYWRtaW5rZXkiLCJpZCI6MX0=", host=grafana_host, port=3000, protocol="http")
dashboard_json=""
mongo_dashboard_json=""
monitoring_json=""
stats_json=""
json_dir_name = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(json_dir_name, "dashboard.json"), "r") as f:
    dashboard_json = json.load(f)

with open(os.path.join(json_dir_name, "mongo-dashboard.json"), "r") as f:
    mongo_dashboard_json = json.load(f)


with open(os.path.join(json_dir_name,"es-monitoring.json"), "r") as f:
    monitoring_json = json.load(f)

with open(os.path.join(json_dir_name, "mongo-stats.json"), "r") as f:
    stats_json= json.load(f)

admin_client.datasources.create(**monitoring_json)
admin_client.datasources.create(**stats_json)
admin_client.dashboards.db.create(dashboard=dashboard_json, overwrite=False)
admin_client.dashboards.db.create(dashboard=mongo_dashboard_json, overwrite=False)
