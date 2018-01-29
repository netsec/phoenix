from copy import deepcopy


def convert_hit_to_template(hit1):
    hit = deepcopy(hit1)
    almost_ready = hit['_source']
    almost_ready['pk'] = hit['_id']
    almost_ready['es_type'] = hit['_type']
    return almost_ready
