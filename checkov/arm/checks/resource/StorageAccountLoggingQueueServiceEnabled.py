from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_check import BaseResourceCheck

# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts
# https://docs.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/queueservices

# https://github.com/MicrosoftDocs/azure-docs/issues/13195

# This check is only relevant for storageAccounts with Queue Service enabled

class StorageAccountLoggingQueueServiceEnabled(BaseResourceCheck):
    def __init__(self):
        # properties.networkAcls.bypass == "AzureServices"
        # Fail if apiVersion less than 2017 as this setting wasn't available
        name = "Ensure Storage logging is enabled for Queue service for read, write and delete requests"
        id = "CKV_AZURE_33"
        supported_resources = ['Microsoft.Storage/storageAccounts/queueServices/providers/diagnosticsettings']
        categories = [CheckCategories.LOGGING]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if (
            "properties" in conf
            and "logs" in conf["properties"]
            and conf["properties"]["logs"]
        ):
            storage = {
                log["category"]: True
                for log in conf["properties"]["logs"]
                if "category" in log
                and "enabled" in log
                and str(log["enabled"]).lower() == "true"
            }

            if (
                "StorageRead" in storage
                and "StorageWrite" in storage
                and "StorageDelete" in storage
                and storage["StorageRead"]
                and storage["StorageWrite"]
                and storage["StorageDelete"]
            ):
                return CheckResult.PASSED
        return CheckResult.FAILED

check = StorageAccountLoggingQueueServiceEnabled()