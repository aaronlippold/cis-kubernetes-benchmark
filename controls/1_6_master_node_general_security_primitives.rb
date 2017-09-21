#
# Copyright 2017, Schuberg Philis B.V.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Kristian Vlaardingerbroek

cis_level = attribute('cis_level', default: '2', description: 'CIS profile level to audit', required: true)

title '1.6 Master Node: General Security Primitives'

control 'cis-kubernetes-benchmark-1.6.1' do
  title 'Ensure that the cluster-admin role is only used where required (Not Scored)'
  desc "The RBAC role `cluster-admin` provides wide-ranging powers over the environment and should be used only where and when needed."
  impact 0.0

  tag rationale: "Kubernetes provides a set of default roles where RBAC is used. Some of these roles such as `cluster-admin` provide wide-ranging privileges which should only be applied where absolutely necessary. Roles such as `cluster-admin` allow super-user access to perform any action on any resource. When used in a `ClusterRoleBinding`, it gives full control over every resource in the cluster and in all namespaces. When used in a `RoleBinding`, it gives full control over every resource in the rolebinding's namespace, including the namespace itself."

  tag check: "Obtain a list of the principals who have access to the `cluster-admin` role by reviewing the `clusterrolebinding` output for each role binding that has access to the `cluster-admin` role.

  `kubectl get clusterrolebindings -o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name`

  Review each principal listed and ensure that cluster-admin privilege is required for it."

  tag fix: "Remove any unneeded `clusterrolebindings`:

  `kubectl delete clusterrolebinding [name]`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.6.1"
  tag cis_level: 1
  tag nist: ['AC-6 (9)', '4']
  tag severity: "medium"

  ref 'user-facing-roles', url: 'https://kubernetes.io/docs/admin/authorization/rbac/#user-facing-roles'

  describe 'cis-kubernetes-benchmark-1.6.1' do
    skip 'Review the output of `kubectl get clusterrolebindings -o=custom-columns=NAME:.metadata.name,ROLE:.roleRef.name,SUBJECT:.subjects[*].name` and ensure the listed principals require `cluster-admin` privileges.'
  end
end

control 'cis-kubernetes-benchmark-1.6.2' do
  title 'Create Pod Security Policies for your cluster (Not Scored)'
  desc "Create and enforce Pod Security Policies for your cluster."
  impact 0.0

  tag rationale: "A Pod Security Policy is a cluster-level resource that controls the actions that a pod can perform and what it has the ability to access. The `PodSecurityPolicy` objects define a set of conditions that a pod must run with in order to be accepted into the system. Pod Security Policies are comprised of settings and strategies that control the security features a pod has access to and hence this must be used to control pod access permissions."

  tag check: "Run the below command and review the Pod Security Policies enforced on the cluster.

  `kubectl get psp`

  Ensure that these policies are configured as per your security requirements."

  tag fix: "Follow the documentation and create and enforce Pod Security Policies for your cluster. Additionally, you could refer the \"CIS Security Benchmark for Docker\" and follow the suggested Pod Security Policies for your environment."

  tag cis_family: ['3', '6.1']
  tag cis_rid: "1.6.2"
  tag cis_level: 1
  tag nist: ['CM-6', '4']
  tag severity: "medium"

  ref 'pod-security-policy', url: 'https://kubernetes.io/docs/concepts/policy/pod-security-policy/'
  ref 'benchmarks.servers.virtualization.docker', url: 'https://benchmarks.cisecurity.org/downloads/browse/index.cfm?category=benchmarks.servers.virtualization.docker'

  describe 'cis-kubernetes-benchmark-1.6.2' do
    skip 'Review the output of `kubectl get psp` and ensure policies are configured per your security requirements.'
  end
end

control 'cis-kubernetes-benchmark-1.6.3' do
  title 'Create administrative boundaries between resources using namespaces (Not Scored)'
  desc "Use namespaces to isolate your Kubernetes objects."
  impact 0.0

  tag rationale: "Limiting the scope of user permissions can reduce the impact of mistakes or malicious activities. A Kubernetes namespace allows you to partition created resources into logically named groups. Resources created in one namespace can be hidden from other namespaces. By default, each resource created by a user in Kubernetes cluster runs in a default namespace, called `default`. You can create additional namespaces and attach resources and users to them. You can use Kubernetes Authorization plugins to create policies that segregate access to namespace resources between different users."

  tag check: "Run the below command and review the namespaces created in the cluster.

  `kubectl get namespaces`

  Ensure that these namespaces are the ones you need and are adequately administered as per your requirements."

  tag fix: "Follow the documentation and create namespaces for objects in your deployment as you need them."

  tag cis_family: ['14', '6.1']
  tag cis_rid: "1.6.3"
  tag cis_level: 1
  tag nist: ['AC-6', '4']
  tag severity: "medium"

  ref 'namespaces', url: 'https://kubernetes.io/docs/concepts/overview/working-with- objects/namespaces/'
  ref 'security-best-practices-kubernetes-deployment.html', url: 'http://blog.kubernetes.io/2016/08/security-best-practices-kubernetes-deployment.html'

  describe 'cis-kubernetes-benchmark-1.6.3' do
    skip 'Review the output of `kubectl get namespaces` and ensure they are the ones you need.'
  end
end

if cis_level == '2'
  control 'cis-kubernetes-benchmark-1.6.4' do
    title 'Create network segmentation using Network Policies (Not Scored)'
    desc "Use network policies to isolate your cluster network."
    impact 0.0

    tag rationale: "Running different applications on the same Kubernetes cluster creates a risk of one compromised application attacking a neighboring application. Network segmentation is important to ensure that containers can communicate only with those they are supposed to. A network policy is a specification of how selections of pods are allowed to communicate with each other and other network endpoints. `NetworkPolicy` resources use labels to select pods and define whitelist rules which allow traffic to the selected pods in addition to what is allowed by the isolation policy for a given namespace."

    tag check: "Run the below command and review the `NetworkPolicy` objects created in the cluster.

    `kubectl get pods --namespace=kube-system`

    Ensure that these `NetworkPolicy` objects are the ones you need and are adequately administered as per your requirements."

    tag fix: "Follow the documentation and create `NetworkPolicy` objects as you need them."

    tag cis_family: ['14.1', '6.1']
    tag cis_rid: "1.6.4"
    tag cis_level: 2
    tag nist: ['AC-4', '4']
  tag severity: "medium"

    ref 'networkpolicies', url: 'https://kubernetes.io/docs/concepts/services-networking/networkpolicies/'
    ref 'security-best-practices-kubernetes-deployment.html', url: 'http://blog.kubernetes.io/2016/08/security-best-practices-kubernetes-deployment.html'
    ref 'declare-network-policy', url: 'https://kubernetes.io/docs/tasks/configure-pod-container/declare-network- policy/'

    describe 'cis-kubernetes-benchmark-1.6.4' do
      skip 'Review the output of `kubectl get pods --namespace=kube-system` and ensure the `NetworkPolicy` objects are the ones you need.'
    end
  end

  control 'cis-kubernetes-benchmark-1.6.5' do
    title 'Ensure that the seccomp profile is set to docker/default in your pod definitions (Not Scored)'
    desc "Enable `docker/default` seccomp profile in your pod definitions."
    impact 0.0

    tag rationale: "Seccomp (secure computing mode) is used to restrict the set of system calls applications can make, allowing cluster administrators greater control over the security of workloads running in the cluster. Kubernetes disables seccomp profiles by default for historical reasons. You should enable it to ensure that the workloads have restricted actions available within the container."

    tag check: "Review the pod definitions in your cluster. It should create a line as below:

    `annotations:
      seccomp.security.alpha.kubernetes.io/pod: docker/default`"

    tag fix: "Seccomp is an alpha feature currently. By default, all alpha features are disabled. So, you would need to enable alpha features in the apiserver by passing `\"--feature- gates=AllAlpha=true\"` argument.

    Edit the `/etc/kubernetes/apiserver` file on the master node and set the `KUBE_API_ARGS` parameter to `\"--feature-gates=AllAlpha=true\"`

    `KUBE_API_ARGS=\"--feature-gates=AllAlpha=true\"`

    Based on your system, restart the `kube-apiserver` service. For example:

    `systemctl restart kube-apiserver.service`

    Use `annotations` to enable the `docker/default` seccomp profile in your pod definitions. An example is as below:

    `apiVersion: v1
    kind: Pod
    metadata:
      name: trustworthy-pod
      annotations:
    seccomp.security.alpha.kubernetes.io/pod: docker/default spec:
      containers:
        - name: trustworthy-container
          image: sotrustworthy:latest`"

    tag cis_family: ['5', '6.1']
    tag cis_rid: "1.6.5"
    tag cis_level: 2
    tag nist: ['AC-6', '4']
  tag severity: "medium"

    ref 'Kubernetes issues 39845', url: 'https://github.com/kubernetes/kubernetes/issues/39845'
    ref 'Kubernetes pull 21790', url: 'https://github.com/kubernetes/kubernetes/pull/21790'
    ref 'examples', url: 'https://github.com/kubernetes/community/blob/master/contributors/design-proposals/seccomp.md#examples'
    ref 'seccomp', url: 'https://docs.docker.com/engine/security/seccomp/'

    describe 'cis-kubernetes-benchmark-1.6.5' do
      skip 'Review all the pod definitions in your cluster and verify that `seccomp` is enabled.'
    end
  end

  control 'cis-kubernetes-benchmark-1.6.6' do
    title 'Apply Security Context to Your Pods and Containers (Not Scored)'
    desc "Apply Security Context to Your Pods and Containers"
    impact 0.0

    tag rationale: "A security context defines the operating system security settings (uid, gid, capabilities, SELinux role, etc..) applied to a container. When designing your containers and pods, make sure that you configure the security context for your pods, containers, and volumes. A security context is a property defined in the deployment yaml. It controls the security parameters that will be assigned to the pod/container/volume. There are two levels of security context: pod level security context, and container level security context."

    tag check: "Review the pod definitions in your cluster and verify that you have security contexts defined as appropriate."

    tag fix: "Follow the Kubernetes documentation and apply security contexts to your pods. For a suggested list of security contexts, you may refer to the CIS Security Benchmark for Docker Containers."

    tag cis_family: ['3', '6.1']
    tag cis_rid: "1.6.6"
    tag cis_level: 2
    tag nist: ['CM-6', '4']
  tag severity: "medium"

    ref 'security-context', url: 'https://kubernetes.io/docs/concepts/policy/security-context/'
    ref 'benchmarks', url: 'https://learn.cisecurity.org/benchmarks'

    describe 'cis-kubernetes-benchmark-1.6.6' do
      skip 'Review the pod definitions in your cluster and verify that you have security contexts defined as appropriate.'
    end
  end

  control 'cis-kubernetes-benchmark-1.6.7' do
    title 'Configure Image Provenance using ImagePolicyWebhook admission controller (Not Scored)'
    desc "Configure Image Provenance for your deployment."
    impact 0.0

    tag rationale: "Kubernetes supports plugging in provenance rules to accept or reject the images in your deployments. You could configure such rules to ensure that only approved images are deployed in the cluster."

    tag check: "Review the pod definitions in your cluster and verify that image provenance is configured as appropriate."

    tag fix: "Follow the Kubernetes documentation and setup image provenance."

    tag cis_family: ['18', '6.1']
    tag cis_rid: "1.6.7"
    tag cis_level: 2
    tag nist: ['SI-1', '4']
  tag severity: "medium"

    ref 'imagepolicywebhook', url: 'https://kubernetes.io/docs/admin/admission-controllers/#imagepolicywebhook'
    ref 'image-provenance', url: 'https://github.com/kubernetes/community/blob/master/contributors/design-proposals/image-provenance.md'
    ref 'anchore-toolbox', url: 'https://hub.docker.com/r/dnurmi/anchore-toolbox/'
    ref 'Kubernetes issues 22888', url: 'https://github.com/kubernetes/kubernetes/issues/22888'

    describe 'cis-kubernetes-benchmark-1.6.7' do
      skip 'Review the pod definitions in your cluster and verify that image provenance is configured as appropriate.'
    end
  end

  control 'cis-kubernetes-benchmark-1.6.8' do
    title 'Configure Network policies as appropriate (Not Scored)'
    desc "Configure Network policies as appropriate."
    impact 0.0

    tag rationale: "The Network Policy API is now stable. Network policy, implemented through a network plug-in, allows users to set and enforce rules governing which pods can communicate with each other. You should leverage it as appropriate in your environment."

    tag check: "Review the network policies enforced and ensure that they are suitable for your requirements."

    tag fix: "Follow the Kubernetes documentation and setup network policies as appropriate.

    For example, you could create a \"default\" isolation policy for a Namespace by creating a NetworkPolicy that selects all pods but does not allow any traffic:

    `apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: default-deny
    spec:
      podSelector:`"

    tag cis_family: ['12', '6.1']
    tag cis_rid: "1.6.8"
    tag cis_level: 2
    tag nist: ['SC-7', '4']
  tag severity: "medium"

    ref 'network-policies', url: 'https://kubernetes.io/docs/concepts/services-networking/network-policies/'

    describe 'cis-kubernetes-benchmark-1.6.8' do
      skip 'Review the network policies enforced and ensure that they are suitable for your requirements.'
    end
  end
end
