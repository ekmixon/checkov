from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_parameter_check import BaseParameterCheck


class SecureStringParameterNoHardcodedValue(BaseParameterCheck):
    def __init__(self):
        name = "SecureString parameter should not have hardcoded default values"
        id = "CKV_AZURE_131"
        supported_resources = ['secureString']
        categories = [CheckCategories.SECRETS]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        # https://docs.microsoft.com/en-us/azure/azure-resource-manager/templates/test-cases#secure-parameters-cant-have-hardcoded-default
        return CheckResult.FAILED if conf.get('defaultValue') else CheckResult.PASSED


check = SecureStringParameterNoHardcodedValue()
