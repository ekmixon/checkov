from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_check import BaseResourceCheck

# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2019-06-01-preview/servers
# https://docs.microsoft.com/en-us/azure/templates/microsoft.sql/2014-04-01/servers/firewallrules

class SQLServerNoPublicAccess(BaseResourceCheck):
    def __init__(self):
        name = "Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)"
        id = "CKV_AZURE_11"
        supported_resources = ['Microsoft.Sql/servers']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

        # API Version 2015-05-01-preview and 2014-04-01

    def scan_resource_conf(self, conf):
        if "resources" in conf and conf["resources"]:
            for resource in conf["resources"]:
                if (
                    "type" in resource
                    and resource["type"]
                    in [
                        "Microsoft.Sql/servers/firewallRules",
                        "firewallRules",
                        "firewallrules",
                    ]
                    and "properties" in resource
                    and (
                        "startIpAddress" in resource["properties"]
                        and resource["properties"]["startIpAddress"]  # nosec
                        in ['0.0.0.0', '0.0.0.0/0']
                        and "endIpAddress" in resource["properties"]
                        and resource["properties"]["endIpAddress"]
                        == '255.255.255.255'
                    )
                ):
                    return CheckResult.FAILED
        return CheckResult.PASSED

check = SQLServerNoPublicAccess()
