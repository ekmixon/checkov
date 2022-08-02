from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class DocDBTLS(BaseResourceCheck):
    def __init__(self):
        name = "Ensure DocDB TLS is not disabled"
        id = "CKV_AWS_90"
        supported_resources = ['AWS::DocDB::DBClusterParameterGroup']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if (
            'Properties' in conf.keys()
            and 'Parameters' in conf['Properties'].keys()
            and 'tls' in conf['Properties']['Parameters'].keys()
            and conf['Properties']['Parameters']['tls'] == "disabled"
        ):
            return CheckResult.FAILED
        return CheckResult.PASSED


check = DocDBTLS()
