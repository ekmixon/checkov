from checkov.common.models.enums import CheckResult, CheckCategories
from checkov.cloudformation.checks.resource.base_resource_check import BaseResourceCheck


class LaunchConfigurationEBSEncryption(BaseResourceCheck):
    def __init__(self):
        name = "Ensure all data stored in the Launch configuration EBS is securely encrypted"
        id = "CKV_AWS_8"
        supported_resources = ['AWS::AutoScaling::LaunchConfiguration']
        categories = [CheckCategories.ENCRYPTION]
        super().__init__(name=name, id=id, categories=categories, supported_resources=supported_resources)

    def scan_resource_conf(self, conf):
        """
        Looks for encryption configuration of device block mapping in an AWS launch configurations
        https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-as-launchconfig-blockdev-template.html
        :param conf: aws_launch_configuration configuration
        :return: <CheckResult>
        """
        if 'Properties' not in conf.keys() or not conf['Properties'].get(
            'BlockDeviceMappings'
        ):
            return CheckResult.FAILED
        ebs_encryption_confs = []
        for block_device_mapping in conf['Properties']['BlockDeviceMappings']:
            if block_device_mapping.get('Ebs') and not block_device_mapping.get('VirtualName'):
                ebs_encryption_confs.append(block_device_mapping['Ebs'].get('Encrypted'))
            else:
                return CheckResult.FAILED
        return CheckResult.PASSED if all(ebs_encryption_confs) else CheckResult.FAILED


check = LaunchConfigurationEBSEncryption()
