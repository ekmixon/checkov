from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check


class KubeControllerManagerServiceAccountPrivateKeyFile(BaseK8Check):
    def __init__(self):
        id = "CKV_K8S_110"
        name = "Ensure that the --service-account-private-key-file argument is set as appropriate"
        categories = [CheckCategories.KUBERNETES]
        supported_entities = ['containers']
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_entities)

    def get_resource_id(self, conf):
        return f'{conf["parent"]} - {conf["name"]}' if conf.get('name') else conf["parent"]

    def scan_spec_conf(self, conf):
        if (
            conf.get("command") is not None
            and "kube-controller-manager" in conf["command"]
        ):
            for command in conf["command"]:
                if command.startswith('--service-account-private-key-file'):
                    file_name = command.split("=")[1]
                    extension = file_name.split(".")[1]
                    return CheckResult.PASSED if extension == 'pem' else CheckResult.FAILED
        return CheckResult.PASSED


check = KubeControllerManagerServiceAccountPrivateKeyFile()
