from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check


class TillerService(BaseK8Check):

    def __init__(self):
        name = "Ensure that the Tiller Service (Helm v2) is deleted"
        id = "CKV_K8S_44"
        # Location: container .image
        supported_kind = ['Service']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def get_resource_id(self, conf):
        if "namespace" in conf["metadata"]:
            return f'{conf["kind"]}.{conf["metadata"]["name"]}.{conf["metadata"]["namespace"]}'

        else:
            return f'{conf["kind"]}.{conf["metadata"]["name"]}.default'

    def scan_spec_conf(self, conf):

        if metadata := conf.get('metadata'):
            if 'name' in metadata and 'tiller' in str(metadata['name']).lower():
                return CheckResult.FAILED
            if labels := metadata.get('labels'):
                for v in labels.values():
                    if 'tiller' in str(v).lower():
                        return CheckResult.FAILED

        if spec := conf.get('spec'):
            if selector := spec.get('selector'):
                for v in selector.values():
                    if 'tiller' in str(v).lower():
                        return CheckResult.FAILED

        return CheckResult.UNKNOWN

check = TillerService()
