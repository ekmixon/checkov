from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck


class UserExists(BaseDockerfileCheck):
    def __init__(self):
        name = "Ensure that a user for the container has been created"
        id = "CKV_DOCKER_3"
        supported_instructions = ["*"]
        categories = [CheckCategories.IAM]
        super().__init__(name=name, id=id, categories=categories, supported_instructions=supported_instructions)

    def scan_entity_conf(self, conf):
        return next(
            (
                (CheckResult.PASSED, conf[instruction][0])
                for instruction, content in conf.items()
                if instruction == "USER"
            ),
            (CheckResult.FAILED, None),
        )


check = UserExists()
