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

title '2.1 Worker Node: Kubelet'

only_if do
  processes('kubelet').exists?
end

control 'cis-kubernetes-benchmark-2.1.1' do
  title 'Ensure that the --allow-privileged argument is set to false (Scored)'
  desc "Do not allow privileged containers."
  impact 1.0

  tag rationale: "The privileged container has all the system capabilities, and it also lifts all the limitations enforced by the device cgroup controller. In other words, the container can then do almost everything that the host can do. This flag exists to allow special use-cases, like running Docker within Docker and hence should be avoided for production workloads."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that the `--allow-privileged` argument is set to `false`."

  tag fix: "Edit the `/etc/kubernetes/config` file on each node and set the `KUBE_ALLOW_PRIV` parameter to `\"--allow-privileged=false\"`:

  `KUBE_ALLOW_PRIV=\"--allow-privileged=false\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "2.1.1"
  tag cis_level: 1
  tag nist: ['AC-6 (9)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref 'security-context', url: 'https://kubernetes.io/docs/user-guide/security-context/'

  describe processes('kubelet').commands.to_s do
    it { should match(/--allow-privileged=false/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.2' do
  title 'Ensure that the --anonymous-auth argument is set to false (Scored)'
  desc "Disable anonymous requests to the Kubelet server."
  impact 1.0

  tag rationale: "When enabled, requests that are not rejected by other configured authentication methods are treated as anonymous requests. These requests are then served by the Kubelet server. You should rely on authentication to authorize access and disallow anonymous requests."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that the `--anonymous-auth` argument is set to `false`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--anonymous-auth=false\"`:

  `KUBELET_ARGS=\"--anonymous-auth=false\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "2.1.2"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref 'kubelet-authentication', url: 'https://kubernetes.io/docs/admin/kubelet-authentication-authorization/#kubelet-authentication'

  describe processes('kubelet').commands.to_s do
    it { should match(/--anonymous-auth=false/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.3' do
  title 'Ensure that the --authorization-mode argument is not set to AlwaysAllow (Scored)'
  desc "Do not allow all requests. Enable explicit authorization."
  impact 1.0

  tag rationale: "Kubelets, by default, allow all authenticated requests (even anonymous ones) without needing explicit authorization checks from the apiserver. You should restrict this behavior and only allow explicitly authorized requests."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that the `--authorization-mode` argument exists and is not set to `AlwaysAllow`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--authorization-mode=Webhook\"`:

  `KUBELET_ARGS=\"--authorization-mode=Webhook\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "2.1.3"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref 'kubelet-authentication', url: 'https://kubernetes.io/docs/admin/kubelet-authentication-authorization/#kubelet-authentication'

  describe processes('kubelet').commands.to_s do
    it { should_not match(/--authorization-mode=(?:.)*AlwaysAllow,*(?:.)*/) }
    it { should match(/--authorization-mode=/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.4' do
  title 'Ensure that the --client-ca-file argument is set as appropriate (Scored)'
  desc "Enable Kubelet authentication using certificates."
  impact 1.0

  tag rationale: "The connections from the apiserver to the kubelet are used for fetching logs for pods, attaching (through kubectl) to running pods, and using the kubelet’s port-forwarding functionality. These connections terminate at the kubelet’s HTTPS endpoint. By default, the apiserver does not verify the kubelet’s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run over untrusted and/or public networks. Enabling Kubelet certificate authentication ensures that the apiserver could authenticate the Kubelet before submitting any requests."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that the `--client-ca-file` argument exists and is set as appropriate."

  tag fix: "Follow the Kubernetes documentation and setup the TLS connection between the apiserver and kubelets. Then, edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--client-ca-file=<path/to/client-ca-file>\"`:

  `KUBELET_ARGS=\"--client-ca-file=<path/to/client-ca-file>\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['14.2', '6.1']
  tag cis_rid: "2.1.4"
  tag cis_level: 1
  tag nist: ['AC-4 (20)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref 'kubelet-authentication', url: 'https://kubernetes.io/docs/admin/kubelet-authentication-authorization/#kubelet-authentication'

  describe processes('kubelet').commands.to_s do
    it { should match(/--client-ca-file=false/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.5' do
  title 'Ensure that the --read-only-port argument is set to 0 (Scored)'
  desc "Disable the read-only port."
  impact 1.0

  tag rationale: "The Kubelet process provides a read-only API in addition to the main Kubelet API. Unauthenticated access is provided to this read-only API which could possibly retrieve potentially sensitive information about the cluster."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that the `--read-only-port` argument exists and is set to `0`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--read-only-port=0\"`

  `KUBELET_ARGS=\"--read-only-port=0\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['9.1', '6.1']
  tag cis_rid: "2.1.5"
  tag cis_level: 1
  tag nist: ['CM-7 (1)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  describe processes('kubelet').commands.to_s do
    it { should match(/--read-only-port=0/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.6' do
  title 'Ensure that the --streaming-connection-idle-timeout argument is not set to 0 (Scored)'
  desc "Do not disable timeouts on streaming connections."
  impact 1.0

  tag rationale: "Setting idle timeouts ensures that you are protected against Denial-of-Service attacks, inactive connections and running out of ephemeral ports. **Note:** By default, `--streaming-connection-idle-timeout` is set to 4 hours which might be too high for your environment. Setting this as appropriate would additionally ensure that such streaming connections are timed out after serving legitimate use cases."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that the `--streaming-connection-idle-timeout` argument is not set to `0`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--streaming-connection-idle-timeout=<appropriate-timeout-value>\"`

  `KUBELET_ARGS=\"--streaming-connection-idle-timeout=5m\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['9', '6.1']
  tag cis_rid: "2.1.6"
  tag cis_level: 1
  tag nist: ['SC-7', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref 'Kubernetes pull 18552', url: 'https://github.com/kubernetes/kubernetes/pull/18552'

  describe processes('kubelet').commands.to_s do
    it { should_not match(/--streaming-connection-idle-timeout=0/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.7' do
  title 'Ensure that the --protect-kernel-defaults argument is set to true (Scored)'
  desc "Protect tuned kernel parameters from overriding kubelet default kernel parameter values."
  impact 1.0

  tag rationale: "Kernel parameters are usually tuned and hardened by the system administrators before putting the systems into production. These parameters protect the kernel and the system. Your kubelet kernel defaults that rely on such parameters should be appropriately set to match the desired secured system state. Ignoring this could potentially lead to running pods with undesired kernel behavior."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that the `--protect-kernel-defaults` argument is set to `true`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--protect-kernel-defaults=true\"`

  `KUBELET_ARGS=\"--protect-kernel-defaults=true\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['3', '6.1']
  tag cis_rid: "2.1.7"
  tag cis_level: 1
  tag nist: ['CM-6', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  describe processes('kubelet').commands.to_s do
    it { should match(/--protect-kernel-defaults=true/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.8' do
  title 'Ensure that the --make-iptables-util-chains argument is set to true (Scored)'
  desc "Allow Kubelet to manage iptables."
  impact 1.0

  tag rationale: "Kubelets can automatically manage the required changes to iptables based on how you choose your networking options for the pods. It is recommended to let kubelets manage the changes to iptables. This ensures that the iptables configuration remains in sync with pods networking configuration. Manually configuring iptables with dynamic pod network configuration changes might hamper the communication between pods/containers and to the outside world. You might have iptables rules too restrictive or too open."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that if the `--make-iptables-util-chains` argument exists then it is set to `true`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and remove the `--make-iptables-util-chains` argument from the `KUBELET_ARGS` parameter. Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['9', '6.1']
  tag cis_rid: "2.1.8"
  tag cis_level: 1
  tag nist: ['SC-7', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  describe processes('kubelet').commands.to_s do
    it { should match(/--make-iptables-util-chains=true/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.9' do
  title 'Ensure that the --keep-terminated-pod-volumes argument is set to false (Scored)'
  desc "Unmount volumes from the nodes on pod termination."
  impact 1.0

  tag rationale: "On pod termination, you should unmount the volumes. Those volumes might have sensitive data that might be exposed if kept mounted on the node without any use. Additionally, such mounted volumes could be modified and later could be mounted on pods. Also, if you retain all mounted volumes for a long time, it might exhaust system resources and you might not be able to mount any more volumes on new pods."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that `--keep-terminated-pod-volumes` argument exists and is set to `false`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--keep-terminated-pod-volumes=false\"`:

  `KUBELET_ARGS=\"--keep-terminated-pod-volumes=false\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "2.1.9"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  describe processes('kubelet').commands.to_s do
    it { should match(/--keep-terminated-pod-volumes=false/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.10' do
  title 'Ensure that the --hostname-override argument is not set (Scored)'
  desc "Do not override node hostnames."
  impact 1.0

  tag rationale: "Overriding hostnames could potentially break TLS setup between the kubelet and the apiserver. Additionally, with overridden hostnames, it becomes increasingly difficult to associate logs with a particular node and process them for security analytics. Hence, you should setup your kubelet nodes with resolvable FQDNs and avoid overriding the hostnames with IPs."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that `--hostname-override` argument does not exist."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_HOSTNAME` parameter to "":

  `KUBELET_HOSTNAME=""`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['3', '6.1']
  tag cis_rid: "2.1.10"
  tag cis_level: 1
  tag nist: ['CM-6', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref 'Kubernetes issues 22063', url: 'https://github.com/kubernetes/kubernetes/issues/22063'

  describe processes('kubelet').commands.to_s do
    it { should_not match(/--hostname-override/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.11' do
  title 'Ensure that the --event-qps argument is set to 0 (Scored)'
  desc "Do not limit event creation."
  impact 1.0

  tag rationale: "It is important to capture all events and not restrict event creation. Events are an important source of security information and analytics that ensure that your environment is consistently monitored using the event data."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that `--event-qps` argument exists and is set to `0`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--event-qps=0\"`:

  `KUBELET_ARGS=\"--event-qps=0\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['6', '6.1']
  tag cis_rid: "2.1.11"
  tag cis_level: 1
  tag nist: ['AU-6', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  describe processes('kubelet').commands.to_s do
    it { should match(/--event-qps=0/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.12' do
  title 'Ensure that the --tls-cert-file and --tls-private-key-file arguments are set as appropriate (Scored)'
  desc "Setup TLS connection on the Kubelets."
  impact 1.0

  tag rationale: "Kubelet communication contains sensitive parameters that should remain encrypted in transit. Configure the Kubelets to serve only HTTPS traffic."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that the `--tls-cert-file` and `--tls-private-key-file` arguments exist and they are set as appropriate."

  tag fix: "Follow the Kubernetes documentation and set up the TLS connection on the Kubelet. Then, edit the `/etc/kubernetes/kubelet` file on the master node and set the `KUBELET_ARGS` parameter to include `\"--tls-cert-file=<path/to/tls-certificate-file>\"` and `\"--tls- private-key-file=<path/to/tls-key-file>\"`:

  `KUBELET_ARGS=\"--tls-cert-file=<path/to/tls-certificate-file> --tls-private- key-file=<path/to/tls-key-file>\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['14.2', '6.1']
  tag cis_rid: "2.1.12"
  tag cis_level: 1
  tag nist: ['AC-4 (20)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref 'securing-the-kubernetes-api', url: 'http://rootsquash.com/2016/05/10/securing-the-kubernetes-api/'
  ref 'docker-kubernetes-tls-guide', url: 'https://github.com/kelseyhightower/docker-kubernetes-tls-guide'

  describe processes('kubelet').commands.to_s do
    it { should match(/--tls-cert-file=/) }
    it { should match(/--tls-private-key-file=/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.13' do
  title 'Ensure that the --cadvisor-port argument is set to 0 (Scored)'
  desc "Disable cAdvisor."
  impact 1.0

  tag rationale: "cAdvisor provides potentially sensitive data and there's currently no way to block access to it using anything other than iptables. It does not require authentication/authorization to connect to the cAdvisor port. Hence, you should disable the port."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that `--cadvisor-port` argument exists and is set to `0`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to `\"--cadvisor-port=0\"`:

  `KUBELET_ARGS=\"--cadvisor-port=0\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['9.1', '6.1']
  tag cis_rid: "2.1.13"
  tag cis_level: 1
  tag nist: ['CM-7 (1)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref 'Kubernetes issues 11710', url: 'https://github.com/kubernetes/kubernetes/issues/11710'
  ref 'Kubernetes issues 32638', url: 'https://github.com/kubernetes/kubernetes/issues/32638'
  ref 'Kubernetes-Attack-Surface-cAdvisor', url: 'https://raesene.github.io/blog/2016/10/14/Kubernetes-Attack-Surface-cAdvisor/'

  describe processes('kubelet').commands.to_s do
    it { should match(/--cadvisor-port=0/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.14' do
  title 'Ensure that the RotateKubeletClientCertificate argument is set to true (Scored)'
  desc "Enable kubelet client certificate rotation."
  impact 1.0

  tag rationale: "RotateKubeletClientCertificate causes the kubelet to rotate its client certificates by creating new CSRs as its existing credentials expire. This automated periodic rotation ensures that the there are no downtimes due to expired certificates and thus addressing availability in the CIA security triad. Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates come from an outside authority/tool (e.g. Vault) then you need to take care of rotation yourself."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that `RotateKubeletClientCertificate` argument exists and is set to `true`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to a value to include `\"--feature-gates=RotateKubeletClientCertificate=true\"`.

  `KUBELET_ARGS=\"--feature-gates=RotateKubeletClientCertificate=true\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['14.2', '6.1']
  tag cis_rid: "2.1.14"
  tag cis_level: 1
  tag nist: ['AC-4 (20)', '4']

  ref 'Kubernetes pull 41912', url: 'https://github.com/kubernetes/kubernetes/pull/41912'
  ref 'kubelet-configuration', url: 'https://kubernetes.io/docs/admin/kubelet-tls-bootstrapping/#kubelet-configuration'

  describe processes('kubelet').commands.to_s do
    it { should match(/--feature-gates=(?:.)*RotateKubeletClientCertificate=true,*(?:.)*/) }
  end
end

control 'cis-kubernetes-benchmark-2.1.15' do
  title 'Ensure that the RotateKubeletServerCertificate argument is set to true (Scored)'
  desc "Enable kubelet server certificate rotation."
  impact 1.0

  tag rationale: "RotateKubeletServerCertificate causes the kubelet to both request a serving certificate after bootstrapping its client credentials and rotate the certificate as its existing credentials expire. This automated periodic rotation ensures that the there are no downtimes due to expired certificates and thus addressing availability in the CIA security triad. Note: This recommendation only applies if you let kubelets get their certificates from the API server. In case your kubelet certificates come from an outside authority/tool (e.g. Vault) then you need to take care of rotation yourself."

  tag check: "Run the following command on each node:

  `ps -ef | grep kubelet`

  Verify that `RotateKubeletServerCertificate` argument exists and is set to `true`."

  tag fix: "Edit the `/etc/kubernetes/kubelet` file on each node and set the `KUBELET_ARGS` parameter to a value to include `\"--feature-gates=RotateKubeletServerCertificate=true\"`.

  `KUBELET_ARGS=\"--feature-gates=RotateKubeletServerCertificate=true\"`

  Based on your system, restart the `kubelet` service. For example:

  `systemctl restart kubelet.service`"

  tag cis_family: ['14.2', '6.1']
  tag cis_rid: "2.1.15"
  tag cis_level: 1
  tag nist: ['AC-4 (20)', '4']

  ref 'Kubernetes pull 45059', url: 'https://github.com/kubernetes/kubernetes/pull/45059'
  ref 'kubelet-configuration', url: 'https://kubernetes.io/docs/admin/kubelet-tls-bootstrapping/#kubelet-configuration'

  describe processes('kube-controller-manager').commands.to_s do
    it { should match(/--feature-gates=(?:.)*RotateKubeletServerCertificate=true,*(?:.)*/) }
  end
end
