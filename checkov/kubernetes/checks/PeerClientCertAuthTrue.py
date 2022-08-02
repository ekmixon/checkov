from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check


class PeerClientCertAuthTrue(BaseK8Check):

    def __init__(self):
        name = "Ensure that the --peer-client-cert-auth argument is set to true"
        id = "CKV_K8S_121"
        supported_kind = ['Pod']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def get_resource_id(self, conf):
        if "namespace" in conf["metadata"]:
            return f'{conf["kind"]}.{conf["metadata"]["name"]}.{conf["metadata"]["namespace"]}'

        else:
            return f'{conf["kind"]}.{conf["metadata"]["name"]}.default'

    def scan_spec_conf(self, conf, entity_type=None):
        if conf.get("metadata")['name'] == 'etcd':
            containers = conf.get('spec')['containers']
            return next(
                (
                    CheckResult.FAILED
                    for container in containers
                    if container.get("args") is not None
                    and '--peer-client-cert-auth=true' not in container['args']
                ),
                CheckResult.PASSED,
            )

        return CheckResult.UNKNOWN


check = PeerClientCertAuthTrue()
