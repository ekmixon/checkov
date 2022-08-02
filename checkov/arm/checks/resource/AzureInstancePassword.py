from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.arm.base_resource_check import BaseResourceCheck


class AzureInstancePassword(BaseResourceCheck):
    def __init__(self):
        name = "Ensure Azure Instance does not use basic authentication(Use SSH Key Instead)"
        id = "CKV_AZURE_1"
        supported_resources = ['Microsoft.Compute/virtualMachines']
        categories = [CheckCategories.GENERAL_SECURITY]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        if "properties" in conf:
            if (
                "storageProfile" in conf["properties"]
                and "imageReference" in conf["properties"]["storageProfile"]
                and "publisher"
                in conf["properties"]["storageProfile"]["imageReference"]
                and "windows"
                in conf["properties"]["storageProfile"]["imageReference"][
                    "publisher"
                ].lower()
            ):
                # This check is not relevant to Windows systems
                return CheckResult.PASSED

            if (
                "osProfile" in conf["properties"]
                and "linuxConfiguration" in conf["properties"]["osProfile"]
                and conf["properties"]["osProfile"]["linuxConfiguration"] != None
                and "disablePasswordAuthentication"
                in conf["properties"]["osProfile"]["linuxConfiguration"]
                and str(
                    conf["properties"]["osProfile"]["linuxConfiguration"][
                        "disablePasswordAuthentication"
                    ]
                ).lower()
                == "true"
            ):
                return CheckResult.PASSED
        return CheckResult.FAILED

check = AzureInstancePassword()
