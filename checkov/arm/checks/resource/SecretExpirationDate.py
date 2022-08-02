from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_check import BaseResourceCheck

# https://docs.microsoft.com/en-us/azure/templates/microsoft.keyvault/vaults/secrets

class SecretExpirationDate(BaseResourceCheck):
    def __init__(self):
        name = "Ensure that the expiration date is set on all secrets"
        id = "CKV_AZURE_41"
        supported_resources = ['Microsoft.KeyVault/vaults/secrets']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if (
            "properties" in conf
            and "attributes" in conf["properties"]
            and "exp" in conf["properties"]["attributes"]
            and conf["properties"]["attributes"]["exp"]
        ):
            return CheckResult.PASSED
        return CheckResult.FAILED

check = SecretExpirationDate()
