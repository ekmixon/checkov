import dpath

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.base_spec_check import BaseK8Check
from checkov.common.util.type_forcers import force_list


class Seccomp(BaseK8Check):

    def __init__(self):
        # CIS-1.5 5.7.2
        name = "Ensure that the seccomp profile is set to docker/default or runtime/default"
        id = "CKV_K8S_31"
        # Location: Pod.metadata.annotations.seccomp.security.alpha.kubernetes.io/pod
        # Location: CronJob.spec.jobTemplate.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/pod
        # Location: *.spec.template.metadata.annotations.seccomp.security.alpha.kubernetes.io/pod
        # Location: *.spec.securityContext.seccompProfile.type
        supported_kind = ['Pod', 'Deployment', 'DaemonSet', 'StatefulSet', 'ReplicaSet', 'ReplicationController', 'Job', 'CronJob']
        categories = [CheckCategories.KUBERNETES]
        super().__init__(name=name, id=id, categories=categories, supported_entities=supported_kind)

    def get_resource_id(self, conf):
        if "namespace" in conf["metadata"]:
            return f'{conf["kind"]}.{conf["metadata"]["name"]}.{conf["metadata"]["namespace"]}'

        else:
            return f'{conf["kind"]}.{conf["metadata"]["name"]}.default'

    def scan_spec_conf(self, conf):
        metadata = {}

        if conf['kind'] == 'Pod':
            if security_profile := dpath.search(
                conf, 'spec/securityContext/seccompProfile/type'
            ):
                security_profile = dpath.get(conf, 'spec/securityContext/seccompProfile/type')
                return CheckResult.PASSED if security_profile == 'RuntimeDefault' else CheckResult.FAILED
            if "metadata" in conf:
                metadata = conf["metadata"]
        if conf['kind'] == 'Deployment':
            if security_profile := dpath.search(
                conf, 'spec/template/spec/securityContext/seccompProfile/type'
            ):
                security_profile = dpath.get(conf, 'spec/template/spec/securityContext/seccompProfile/type')
                return CheckResult.PASSED if security_profile == 'RuntimeDefault' else CheckResult.FAILED
            if "metadata" in conf:
                metadata = conf["metadata"]
        if conf['kind'] == 'StatefulSet':
            if security_profile := dpath.search(
                conf, 'spec/template/spec/securityContext/seccompProfile/type'
            ):
                security_profile = dpath.get(conf, 'spec/template/spec/securityContext/seccompProfile/type')
                return CheckResult.PASSED if security_profile == 'RuntimeDefault' else CheckResult.FAILED
            if "metadata" in conf:
                metadata = conf["metadata"]
        elif conf['kind'] == 'CronJob':
            if (
                "spec" in conf
                and "jobTemplate" in conf["spec"]
                and "spec" in conf["spec"]["jobTemplate"]
                and "template" in conf["spec"]["jobTemplate"]["spec"]
                and "metadata" in conf["spec"]["jobTemplate"]["spec"]["template"]
            ):
                metadata = conf["spec"]["jobTemplate"]["spec"]["template"]["metadata"]
        else:
            inner_metadata = self.get_inner_entry(conf, "metadata")
            metadata = inner_metadata or metadata

        if metadata and metadata.get('annotations'):
            for annotation in force_list(metadata["annotations"]):
                for key in annotation:
                    if "seccomp.security.alpha.kubernetes.io/pod" in key and (
                        "docker/default" in annotation[key]
                        or "runtime/default" in annotation[key]
                    ):
                        return CheckResult.PASSED
        return CheckResult.FAILED


check = Seccomp()
