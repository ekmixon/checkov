from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_check import BaseResourceCheck

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2017-03-01-preview/servers/securityalertpolicies

class SQLServerEmailAlertsEnabled(BaseResourceCheck):
    def __init__(self):
        name = "Ensure that 'Send Alerts To' is enabled for MSSQL servers"
        id = "CKV_AZURE_26"
        supported_resources = ['Microsoft.Sql/servers/databases']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "resources" in conf and conf["resources"]:
            for resource in conf["resources"]:
                if (
                    "type" in resource
                    and resource["type"]
                    in [
                        "Microsoft.Sql/servers/databases/securityAlertPolicies",
                        "securityAlertPolicies",
                    ]
                    and "properties" in resource
                    and "state" in resource["properties"]
                    and resource["properties"]["state"].lower() == "enabled"
                    and "emailAddresses" in resource["properties"]
                    and resource["properties"]["emailAddresses"]
                ):
                    return CheckResult.PASSED

        return CheckResult.FAILED

check = SQLServerEmailAlertsEnabled()
