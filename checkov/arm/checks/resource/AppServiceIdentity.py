from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_check import BaseResourceCheck

# https://docs.microsoft.com/en-us/azure/templates/microsoft.web/2019-08-01/sites#ManagedServiceIdentity
# https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity
# https://docs.microsoft.com/en-us/azure/app-service/samples-resource-manager-templates

class AppServiceIdentity(BaseResourceCheck):
    def __init__(self):
        name = "Ensure that Register with Azure Active Directory is enabled on App Service"
        id = "CKV_AZURE_16"
        supported_resources = ['Microsoft.Web/sites']
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if (
            "identity" in conf
            and "type" in conf["identity"]
            and (
                conf["identity"]["type"] != "SystemAssigned"
                and conf["identity"]["type"] == "UserAssigned"
                and "userAssignedIdentities" in conf["identity"]
                and conf["identity"]["userAssignedIdentities"]
                or conf["identity"]["type"] == "SystemAssigned"
            )
        ):
            return CheckResult.PASSED
        return CheckResult.FAILED

check = AppServiceIdentity()