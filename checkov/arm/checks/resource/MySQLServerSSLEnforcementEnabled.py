from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_check import BaseResourceCheck

class MySQLServerSSLEnforcementEnabled(BaseResourceCheck):
    def __init__(self):
        name = "Ensure 'Enforce SSL connection' is set to 'ENABLED' for MySQL Database Server"
        id = "CKV_AZURE_28"
        supported_resources = ['Microsoft.DBforMySQL/servers']
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if (
            "properties" in conf
            and "sslEnforcement" in conf["properties"]
            and str(conf["properties"]["sslEnforcement"]).lower() == "enabled"
        ):
            return CheckResult.PASSED
        return CheckResult.FAILED

check = MySQLServerSSLEnforcementEnabled()
