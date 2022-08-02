
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check


class DefaultServiceAccount(BaseK8Check):

    def __init__(self):
        # CIS-1.5 5.1.5
        name = "Ensure that default service accounts are not actively used"
        # Check automountServiceAccountToken in default service account in runtime
        id = "CKV_K8S_41"
        supported_kind = ['ServiceAccount']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def get_resource_id(self, conf):
        return (
            f'ServiceAccount.{conf["metadata"]["name"]}.{conf["metadata"]["namespace"]}'
            if "namespace" in conf["metadata"]
            else f'ServiceAccount.{conf["metadata"]["name"]}.default'
        )

    def scan_spec_conf(self, conf):
        if "metadata" in conf and "name" in conf["metadata"]:
            if conf["metadata"]["name"] != "default":
                return CheckResult.PASSED
            if (
                "automountServiceAccountToken" in conf
                and conf["automountServiceAccountToken"] == False
            ):
                return CheckResult.PASSED
            return CheckResult.FAILED
        return CheckResult.PASSED

check = DefaultServiceAccount()



