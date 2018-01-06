from copy import deepcopy


def convert_hit_to_template(hit1):
    hit = deepcopy(hit1)
    almost_ready = hit['_source']
    almost_ready['pk'] = hit['_id']
    return almost_ready
