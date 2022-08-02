from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check


class Secrets(BaseK8Check):

    def __init__(self):
        # CIS-1.5 5.4.1
        name = "Prefer using secrets as files over secrets as environment variables"
        id = "CKV_K8S_35"
        # Location: container .env
        supported_kind = ['containers', 'initContainers']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def get_resource_id(self, conf):
        return f'{conf["parent"]} - {conf["name"]}' if conf.get('name') else conf["parent"]

    def scan_spec_conf(self, conf):
        if "env" in conf and conf["env"]:
            for e in conf["env"]:
                if "valueFrom" in e and "secretKeyRef" in e["valueFrom"]:
                    return CheckResult.FAILED
        if "envFrom" in conf and conf["envFrom"]:
            for ef in conf["envFrom"]:
                if "secretRef" in ef:
                    return CheckResult.FAILED
        return CheckResult.PASSED

check = Secrets()