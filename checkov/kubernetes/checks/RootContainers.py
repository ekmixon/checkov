
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check


class RootContainers(BaseK8Check):

    def __init__(self):
        # CIS-1.3 1.7.6
        # CIS-1.5 5.2.6
        name = "Minimize the admission of root containers"
        # Check runAsNonRoot.  If false, then ensure runAsUser > 0
        # Location: Pod.spec.runAsUser / runAsNonRoot
        # Location: CronJob.spec.jobTemplate.spec.template.spec.securityContext.runAsUser / runAsNonRoot
        # Location: *.spec.template.spec.securityContext.runAsUser / runAsNonRoot
        id = "CKV_K8S_23"
        supported_kind = ['Pod', 'Deployment', 'DaemonSet', 'StatefulSet', 'ReplicaSet', 'ReplicationController', 'Job', 'CronJob']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)



    def get_resource_id(self, conf):
        if "namespace" in conf["metadata"]:
            return f'{conf["kind"]}.{conf["metadata"]["name"]}.{conf["metadata"]["namespace"]}'

        else:
            return f'{conf["kind"]}.{conf["metadata"]["name"]}.default'

    def scan_spec_conf(self, conf):
        spec = {}

        if conf['kind'] == 'Pod':
            if "spec" in conf:
                spec = conf["spec"]
        elif conf['kind'] == 'CronJob':
            if (
                "spec" in conf
                and "jobTemplate" in conf["spec"]
                and "spec" in conf["spec"]["jobTemplate"]
                and "template" in conf["spec"]["jobTemplate"]["spec"]
                and "spec" in conf["spec"]["jobTemplate"]["spec"]["template"]
            ):
                spec = conf["spec"]["jobTemplate"]["spec"]["template"]["spec"]
        else:
            inner_spec = self.get_inner_entry(conf, "spec")
            spec = inner_spec or spec

        # Collect results
        if spec:
            results = {"pod": {}, "container": []}
            results["pod"]["runAsNonRoot"] = check_runAsNonRoot(spec)
            results["pod"]["runAsUser"] = check_runAsUser(spec)

            if spec.get("containers"):
                for c in spec["containers"]:
                    cresults = {"runAsNonRoot": check_runAsNonRoot(c)}
                    cresults["runAsUser"] = check_runAsUser(c)
                    results["container"].append(cresults)

            for cr in results["container"]:
                if results["pod"]["runAsNonRoot"] == "PASSED":
                    if cr["runAsNonRoot"] == "FAILED" and cr["runAsUser"] in [
                        "FAILED",
                        "ABSENT",
                    ]:
                        return CheckResult.FAILED
                elif results["pod"]["runAsUser"] == "PASSED":
                            # Pod runAsNonRoot == False (or absent) ; Pod runAsUser > 0 (PASSED)
                # If container runAsUser FAILED, then overall fail as it overrides pod (FAILED)
                    if cr["runAsUser"] == "FAILED":
                        return CheckResult.FAILED
                else:
                            # Pod runAsNonRoot and runAsUser failed or absent
                #   If container runAsNonRoot true (PASSED)
                #   If container runAsNonRoot failed or absent, but runAsUser passed (PASSED)
                #   If container runAsNonRoot failed or absent, but runAsUser failed/absent (FAILED)
                    if cr["runAsNonRoot"] == "PASSED":
                        continue
                    if (
                        cr["runAsNonRoot"] in ["FAILED", "ABSENT"]
                        and cr["runAsUser"] != "PASSED"
                    ):
                        return CheckResult.FAILED
            return CheckResult.PASSED
        return CheckResult.FAILED

check = RootContainers()

def check_runAsNonRoot(spec):
    if "securityContext" in spec and "runAsNonRoot" in spec["securityContext"]:
        return "PASSED" if spec["securityContext"]["runAsNonRoot"] else "FAILED"
    return "ABSENT"

def check_runAsUser(spec):
    if "securityContext" in spec and "runAsUser" in spec["securityContext"]:
        return "PASSED" if spec["securityContext"]["runAsUser"] > 0 else "FAILED"
    return "ABSENT"


