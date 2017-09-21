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

title '2.2 Worker Node: Configuration Files'

control 'cis-kubernetes-benchmark-2.2.1' do
  title 'Ensure that the config file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the `config` file has permissions of `644` or more restrictive."
  impact 1.0

  tag rationale: "The `config` file controls various parameters that set the behavior of various components of the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `stat -c %a /etc/kubernetes/config`

  Verify that the permissions are `644` or more restrictive."

  tag fix: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `chmod 644 /etc/kubernetes/config`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "2.2.1"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  only_if do
    file('/etc/kubernetes/config').exist?
  end

  describe file('/etc/kubernetes/config').mode.to_s do
    it { should match(/[0246][024][024]/) }
  end
end

control 'cis-kubernetes-benchmark-2.2.2' do
  title 'Ensure that the config file ownership is set to root:root (Scored)'
  desc "Ensure that the `config` file ownership is set to `root:root`."
  impact 1.0

  tag rationale: "The `config` file controls various parameters that set the behavior of various components of the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by `root:root`."

  tag check: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `stat -c %U:%G /etc/kubernetes/config`

  Verify that the ownership is set to `root:root`."

  tag fix: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `chown root:root /etc/kubernetes/config`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "2.2.2"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  only_if do
    file('/etc/kubernetes/config').exist?
  end

  describe file('/etc/kubernetes/config') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-kubernetes-benchmark-2.2.3' do
  title 'Ensure that the kubelet file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the `kubelet` file has permissions of `644` or more restrictive."
  impact 1.0

  tag rationale: "The `kubelet` file controls various parameters that set the behavior of the `kubelet` service in the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `stat -c %a /etc/kubernetes/kubelet`

  Verify that the permissions are `644` or more restrictive."

  tag fix: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `chmod 644 /etc/kubernetes/kubelet`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "2.2.3"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref '44-joining-your-noes', url: 'https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#44-joining-your-nodes'

  only_if do
    file('/etc/kubernetes/kubelet').exist?
  end

  describe file('/etc/kubernetes/kubelet').mode.to_s do
    it { should match(/[0246][024][024]/) }
  end
end

control 'cis-kubernetes-benchmark-2.2.4' do
  title 'Ensure that the kubelet file ownership is set to root:root (Scored)'
  desc "Ensure that the `kubelet` file ownership is set to `root:root`."
  impact 1.0

  tag rationale: "The `kubelet` file controls various parameters that set the behavior of the `kubelet` service in the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by `root:root`."

  tag check: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `stat -c %U:%G /etc/kubernetes/kubelet`

  Verify that the ownership is set to `root:root`."

  tag fix: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `chown root:root /etc/kubernetes/kubelet`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "2.2.4"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'
  ref '44-joining-your-noes', url: 'https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#44-joining-your-nodes'

  only_if do
    file('/etc/kubernetes/kubelet').exist?
  end

  describe file('/etc/kubernetes/kubelet') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-kubernetes-benchmark-2.2.5' do
  title 'Ensure that the proxy file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the `proxy` file has permissions of `644` or more restrictive."
  impact 1.0

  tag rationale: "The `proxy` file controls various parameters that set the behavior of the `kube-proxy` service in the worker node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `stat -c %a /etc/kubernetes/proxy`

  Verify that the permissions are `644` or more restrictive."

  tag fix: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `chmod 644 /etc/kubernetes/proxy`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "2.2.5"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  only_if do
    file('/etc/kubernetes/proxy').exist?
  end

  describe file('/etc/kubernetes/proxy').mode.to_s do
    it { should match(/[0246][024][024]/) }
  end
end

control 'cis-kubernetes-benchmark-2.2.6' do
  title 'Ensure that the proxy file ownership is set to root:root (Scored)'
  desc "Ensure that the `proxy` file ownership is set to `root:root`."
  impact 1.0

  tag rationale: "The `proxy` file controls various parameters that set the behavior of the `kube-proxy` service in the worker node. You should set its file ownership to maintain the integrity of the file. The file should be owned by `root:root`."

  tag check: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `stat -c %U:%G /etc/kubernetes/proxy`

  Verify that the ownership is set to `root:root`."

  tag fix: "Run the below command (based on the file location on your system) on the each worker node. For example,

  `chown root:root /etc/kubernetes/proxy`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "2.2.6"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kubelet', url: 'https://kubernetes.io/docs/admin/kubelet/'

  only_if do
    file('/etc/kubernetes/proxy').exist?
  end

  describe file('/etc/kubernetes/proxy') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-kubernetes-benchmark-2.2.7' do
  title 'Ensure that the certificate authorities file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the certificate authorities file has permissions of 644 or more restrictive."
  impact 1.0

  tag rationale: "The certificate authorities file controls the authorities used to validate API requests. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the following command:

  `ps -ef | grep kubelet`

  Find the file specified by the `--client-ca-file` argument.

  Run the following command:

  `stat -c %a <filename>`

  Verify that the permissions are `644` or more restrictive."

  tag fix: "Run the following command to modify the file permissions of the `--client-ca-file `

  `chmod 644 <filename>`"

  tag cis_family: ['5.1', '6.1']
  tag cis_family: ['14.4', '6.1']
  tag cis_rid: "2.2.7"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'x509-client-certs', url: 'https://kubernetes.io/docs/admin/authentication/#x509-client-certs'

  ca_cert_path = processes('kubelet').commands.to_s.scan(/--client-ca-file=(\S*)/)

  if ca_cert_path.empty?
    describe 'cis-kubernetes-benchmark-2.2.7' do
      skip 'No client CA file specified for `kubelet` process'
    end
  else
    describe file(ca_cert_path.last.first).mode.to_s do
      it { should match(/[0246][024][024]/) }
    end
  end
end

control 'cis-kubernetes-benchmark-2.2.8' do
  title 'Ensure that the client certificate authorities file ownership is set to root:root (Scored)'
  desc "Ensure that the certificate authorities file ownership is set to root:root."
  impact 1.0

  tag rationale: "The certificate authorities file controls the authorities used to validate API requests. You should set its file ownership to maintain the integrity of the file. The file should be owned by root:root."

  tag check: "Run the following command:

  `ps -ef | grep kubelet`

  Find the file specified by the `--client-ca-file` argument.

  Run the following command:

  `stat -c %U:%G <filename>`

  Verify that the ownership is set to `root:root`."

  tag fix: "Run the following command to modify the ownership of the `--client-ca-file`.

  `chown root:root <filename>`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "2.2.8"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'x509-client-certs', url: 'https://kubernetes.io/docs/admin/authentication/#x509-client-certs'

  ca_cert_path = processes('kubelet').commands.to_s.scan(/--client-ca-file=(\S*)/)

  if ca_cert_path.empty?
    describe 'cis-kubernetes-benchmark-2.2.8' do
      skip 'No client CA file specified for `kubelet` process'
    end
  else
    describe file(ca_cert_path.last.first) do
      it { should be_owned_by 'root' }
      it { should be_grouped_into 'root' }
    end
  end
end
