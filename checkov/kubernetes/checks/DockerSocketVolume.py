
from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check


class DockerSocketVolume(BaseK8Check):

    def __init__(self):
        name = "Do not expose the docker daemon socket to containers"
        # Exposing the socket gives container information and increases risk of exploit
        # read-only is not a solution but only makes it harder to exploit.
        # Location: Pod.spec.volumes[].hostPath.path
        # Location: CronJob.spec.jobTemplate.spec.template.spec.volumes[].hostPath.path
        # Location: *.spec.template.spec.volumes[].hostPath.path
        id = "CKV_K8S_27"
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

        # Evaluate volumes
        if spec and "volumes" in spec and spec.get("volumes"):
            for v in spec["volumes"]:
                if (
                    v.get("hostPath")
                    and "path" in v["hostPath"]
                    and v["hostPath"]["path"] == "/var/run/docker.sock"
                ):
                    return CheckResult.FAILED
        return CheckResult.PASSED

check = DockerSocketVolume()
