import json


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        return list(o) if isinstance(o, set) else json.JSONEncoder.default(self, o)
