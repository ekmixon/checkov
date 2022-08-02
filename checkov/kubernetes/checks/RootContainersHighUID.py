
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check


class RootContainersHighUID(BaseK8Check):

    def __init__(self):
        name = "Containers should run as a high UID to avoid host conflict"
        # runAsUser should be >= 10000 at pod spec or container level
        # Location: Pod.spec.runAsUser
        # Location: CronJob.spec.jobTemplate.spec.template.spec.securityContext.runAsUser
        # Location: *.spec.template.spec.securityContext.runAsUser
        id = "CKV_K8S_40"
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
            results["pod"]["runAsUser"] = check_runAsUser(spec)

            if spec.get("containers"):
                for c in spec["containers"]:
                    cresults = {"runAsUser": check_runAsUser(c)}
                    results["container"].append(cresults)

            if results["pod"]["runAsUser"] == "PASSED":
                return next(
                    (
                        CheckResult.FAILED
                        for cr in results["container"]
                        if cr["runAsUser"] == "FAILED"
                    ),
                    CheckResult.PASSED,
                )

            containeroverride = False
            for cr in results["container"]:
                if cr["runAsUser"] in ["FAILED", "ABSENT"]:
                    return CheckResult.FAILED
                elif cr["runAsUser"] == "PASSED":
                    containeroverride = True
            return CheckResult.PASSED if containeroverride else CheckResult.FAILED
        return CheckResult.FAILED

check = RootContainersHighUID()

def check_runAsUser(spec):
    if "securityContext" in spec and "runAsUser" in spec["securityContext"]:
        return "PASSED" if spec["securityContext"]["runAsUser"] >= 10000 else "FAILED"
    return "ABSENT"


