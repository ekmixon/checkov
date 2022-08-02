from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.dockerfile.base_dockerfile_check import BaseDockerfileCheck


class HealthcheckExists(BaseDockerfileCheck):
    def __init__(self):
        name = "Ensure that HEALTHCHECK instructions have been added to container images "
        id = "CKV_DOCKER_2"
        supported_instructions = ["*"]
        categories = [CheckCategories.NETWORKING]
        super().__init__(name=name, id=id, categories=categories, supported_instructions=supported_instructions)

    def scan_entity_conf(self, conf):
        return next(
            (
                (CheckResult.PASSED, conf[instruction][0])
                for instruction, content in conf.items()
                if instruction == "HEALTHCHECK"
            ),
            (CheckResult.FAILED, None),
        )


check = HealthcheckExists()
