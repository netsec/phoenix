from copy import deepcopy


def convert_hit_to_template(hit1):
    almost_ready = hit1['_source']
    almost_ready['pk'] = hit1['_id']
    almost_ready['es_index'] = hit1['_index']
    almost_ready['es_type'] = hit1['_type']
    return almost_ready
