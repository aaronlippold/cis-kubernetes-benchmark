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

title '1.4 Master Node: Configuration Files'

control 'cis-kubernetes-benchmark-1.4.1' do
  title 'Ensure that the apiserver file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the `apiserver` file has permissions of `644` or more restrictive."
  impact 1.0

  tag rationale: "The `apiserver` file controls various parameters that set the behavior of the API server. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %a /etc/kubernetes/apiserver`

  Verify that the permissions are `644` or more restrictive."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chmod 644 /etc/kubernetes/apiserver`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.1"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kube-apiserver', url: 'https://kubernetes.io/docs/admin/kube-apiserver/'

  only_if do
    file('/etc/kubernetes/apiserver').exist?
  end

  describe file('/etc/kubernetes/apiserver').mode.to_s do
    it { should match(/[0246][024][024]/) }
  end
end

control 'cis-kubernetes-benchmark-1.4.2' do
  title 'Ensure that the apiserver file ownership is set to root:root (Scored)'
  desc "Ensure that the `apiserver` file ownership is set to `root:root`."
  impact 1.0

  tag rationale: "The `apiserver` file controls various parameters that set the behavior of the API server. You should set its file ownership to maintain the integrity of the file. The file should be owned by `root:root`."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %U:%G /etc/kubernetes/apiserver`

  Verify that the ownership is set to `root:root`."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chown root:root /etc/kubernetes/apiserver`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.2"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kube-apiserver', url: 'https://kubernetes.io/docs/admin/kube-apiserver/'

  only_if do
    file('/etc/kubernetes/apiserver').exist?
  end

  describe file('/etc/kubernetes/apiserver') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-kubernetes-benchmark-1.4.3' do
  title 'Ensure that the config file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the `config` file has permissions of `644` or more restrictive."
  impact 1.0

  tag rationale: "The `config` file controls various parameters that set the behavior of various components of the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %a /etc/kubernetes/config`

  Verify that the permissions are `644` or more restrictive."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chmod 644 /etc/kubernetes/config`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.3"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kube-apiserver', url: 'https://kubernetes.io/docs/admin/kube-apiserver/'

  only_if do
    file('/etc/kubernetes/config').exist?
  end

  describe file('/etc/kubernetes/config').mode.to_s do
    it { should match(/[0246][024][024]/) }
  end
end

control 'cis-kubernetes-benchmark-1.4.4' do
  title 'Ensure that the config file ownership is set to root:root (Scored)'
  desc "Ensure that the `config` file ownership is set to `root:root`."
  impact 1.0

  tag rationale: "The `config` file controls various parameters that set the behavior of various components of the master node. You should set its file ownership to maintain the integrity of the file. The file should be owned by `root:root`."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %U:%G /etc/kubernetes/config`

  Verify that the ownership is set to `root:root`."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chown root:root /etc/kubernetes/config`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.4"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kube-apiserver', url: 'https://kubernetes.io/docs/admin/kube-apiserver/'

  only_if do
    file('/etc/kubernetes/config').exist?
  end

  describe file('/etc/kubernetes/config') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-kubernetes-benchmark-1.4.5' do
  title 'Ensure that the scheduler file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the `scheduler` file has permissions of `644` or more restrictive."
  impact 1.0

  tag rationale: "The `scheduler` file controls various parameters that set the behavior of the `kube-scheduler` service in the master node. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %a /etc/kubernetes/scheduler`

  Verify that the permissions are `644` or more restrictive."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chmod 644 /etc/kubernetes/scheduler`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.5"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kube-apiserver', url: 'https://kubernetes.io/docs/admin/kube-apiserver/'

  only_if do
    file('/etc/kubernetes/scheduler').exist?
  end

  describe file('/etc/kubernetes/scheduler').mode.to_s do
    it { should match(/[0246][024][024]/) }
  end
end

control 'cis-kubernetes-benchmark-1.4.6' do
  title 'Ensure that the scheduler file ownership is set to root:root (Scored)'
  desc "Ensure that the `scheduler` file ownership is set to `root:root`."
  impact 1.0

  tag rationale: "The `scheduler` file controls various parameters that set the behavior of the `kube-scheduler` service in the master node. You should set its file ownership to maintain the integrity of the file. The file should be owned by `root:root`."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %U:%G /etc/kubernetes/scheduler`

  Verify that the ownership is set to `root:root`."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chown root:root /etc/kubernetes/scheduler`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.6"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'kube-apiserver', url: 'https://kubernetes.io/docs/admin/kube-apiserver/'

  only_if do
    file('/etc/kubernetes/scheduler').exist?
  end

  describe file('/etc/kubernetes/scheduler') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-kubernetes-benchmark-1.4.7' do
  title 'Ensure that the etcd.conf file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the `etcd.conf` file has permissions of `644` or more restrictive."
  impact 1.0

  tag rationale: "The `etcd.conf` file controls various parameters that set the behavior of the `etcd` service in the master node. etcd is a highly-available key value store which Kubernetes uses for persistent storage of all of its REST API object. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %a /etc/etcd/etcd.conf`

  Verify that the permissions are `644` or more restrictive."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chmod 644 /etc/etcd/etcd.conf`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.7"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'coreos-etcd', url: 'https://coreos.com/etcd'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'

  only_if do
    file('/etc/etcd/etcd.conf').exist?
  end

  describe file('/etc/etcd/etcd.conf').mode.to_s do
    it { should match(/[0246][024][024]/) }
  end
end

control 'cis-kubernetes-benchmark-1.4.8' do
  title 'Ensure that the etcd.conf file ownership is set to root:root (Scored)'
  desc "Ensure that the `etcd.conf` file ownership is set to `root:root`."
  impact 1.0

  tag rationale: "The `etcd.conf` file controls various parameters that set the behavior of the `etcd` service in the master node. etcd is a highly-available key value store which Kubernetes uses for persistent storage of all of its REST API object. You should set its file ownership to maintain the integrity of the file. The file should be owned by `root:root`."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %U:%G /etc/etcd/etcd.conf`

  Verify that the ownership is set to `root:root`."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chown root:root /etc/etcd/etcd.conf`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.8"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'coreos-etcd', url: 'https://coreos.com/etcd'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'

  only_if do
    file('/etc/etcd/etcd.conf').exist?
  end

  describe file('/etc/etcd/etcd.conf') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-kubernetes-benchmark-1.4.9' do
  title 'Ensure that the flanneld file permissions are set to 644 or more restrictive (Scored)'
  desc "Ensure that the `flanneld` file has permissions of `644` or more restrictive."
  impact 1.0

  tag rationale: "The `flanneld` file controls various parameters that set the behavior of the `flanneld` service in the master node. Flannel is one of the various options for a simple overlay network. You should restrict its file permissions to maintain the integrity of the file. The file should be writable by only the administrators on the system."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %a /etc/sysconfig/flanneld`

  Verify that the permissions are `644` or more restrictive.

  Note: Flannel is an optional component of Kubernetes. If you are not using Flannel then this requirement is not applicable. If you are using any other option for configuring your networking, please extend this recommendation to cover important configuration files as appropriate."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  `chmod 644 /etc/sysconfig/flanneld`"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.9"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'coreos-flannel', url: 'https://coreos.com/flannel/docs/latest/'
  ref 'flannel', url: 'https://kubernetes.io/docs/concepts/cluster-administration/networking/#flannel'

  only_if do
    file('/etc/sysconfig/flanneld').exist?
  end

  describe file('/etc/sysconfig/flanneld').mode.to_s do
    it { should match(/[0246][024][024]/) }
  end
end

control 'cis-kubernetes-benchmark-1.4.10' do
  title 'Ensure that the flanneld file ownership is set to root:root (Scored)'
  desc "Ensure that the `flanneld` file ownership is set to `root:root`."
  impact 1.0

  tag rationale: "The `flanneld` file controls various parameters that set the behavior of the `flanneld` service in the master node. Flannel is one of the various options for a simple overlay network. You should set its file ownership to maintain the integrity of the file. The file should be owned by `root:root`."

  tag check: "Run the below command (based on the file location on your system) on the master node. For example,

  `stat -c %U:%G /etc/sysconfig/flanneld`

  Verify that the ownership is set to `root:root`.

  Note: Flannel is an optional component of Kubernetes. If you are not using Flannel then this requirement is not applicable. If you are using any other option for configuring your networking, please extend this recommendation to cover important configuration files as appropriate."

  tag fix: "Run the below command (based on the file location on your system) on the master node. For example,

  chown root:root /etc/sysconfig/flanneld"

  tag cis_family: ['5.1', '6.1']
  tag cis_rid: "1.4.10"
  tag cis_level: 1
  tag nist: ['AC-6(9)', '4']

  ref 'coreos-flannel', url: 'https://coreos.com/flannel/docs/latest/'
  ref 'flannel', url: 'https://kubernetes.io/docs/concepts/cluster-administration/networking/#flannel'

  only_if do
    file('/etc/sysconfig/flanneld').exist?
  end

  describe file('/etc/sysconfig/flanneld') do
    it { should be_owned_by 'root' }
    it { should be_grouped_into 'root' }
  end
end

control 'cis-kubernetes-benchmark-1.4.11' do
  title 'Ensure that the etcd data directory permissions are set to 700 or more restrictive (Scored)'
  desc "Ensure that the etcd data directory has permissions of `700` or more restrictive."
  impact 1.0

  tag rationale: "etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. This data directory should be protected from any unauthorized reads or writes. It should not be readable or writable by any group members or the world."

  tag check: "On the etcd server node, get the etcd data directory, passed as an argument `--data-dir`, from the below command:

  `ps -ef | grep etcd`

  Run the below command (based on the etcd data directory found above). For example,

  `stat -c %a /var/lib/etcd/default.etcd`

  Verify that the permissions are `700` or more restrictive."

  tag fix: "On the etcd server node, get the etcd data directory, passed as an argument `--data-dir`, from the below command:

  `ps -ef | grep etcd`

  Run the below command (based on the etcd data directory found above). For example,

  `chmod 700 /var/lib/etcd/default.etcd`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "1.4.11"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'data-dir', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#data-dir'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'

  etcd_process = processes(Regexp.new(%r{/usr/bin/etcd}))
  data_dir = ''

  catch(:stop) do
    if etcd_process.exists?
      if (data_dir = etcd_process.commands.to_s.scan(/--data-dir=(\S+)/).last)
        data_dir = data_dir.first
        throw :stop
      end

      if (data_dir = file("/proc/#{etcd_process.pids.first}/environ").content.split("\0").select { |i| i[/^ETCD_DATA_DIR/] }.first.split('=').last)
        throw :stop
      end
    end
  end

  if !data_dir.empty?
    describe file(data_dir).mode.to_s do
      it { should match(/[01234567]00/) }
    end
  else
    describe 'cis-kubernetes-benchmark-1.4.11' do
      skip 'etcd data directory not found'
    end
  end
end

control 'cis-kubernetes-benchmark-1.4.12' do
  title 'Ensure that the etcd data directory ownership is set to etcd:etcd (Scored)'
  desc "Ensure that the etcd data directory ownership is set to `etcd:etcd`."
  impact 1.0

  tag rationale: "etcd is a highly-available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. This data directory should be protected from any unauthorized reads or writes. It should be owned by `etcd:etcd`."

  tag check: "On the etcd server node, get the etcd data directory, passed as an argument `--data-dir`, from the below command:

  `ps -ef | grep etcd`

  Run the below command (based on the etcd data directory found above). For example,

  `stat -c %U:%G /var/lib/etcd/default.etcd`

  Verify that the ownership is set to `etcd:etcd`."

  tag fix: "On the etcd server node, get the etcd data directory, passed as an argument `--data-dir`, from the below command:

  `ps -ef | grep etcd`

  Run the below command (based on the etcd data directory found above). For example,

  `chown etcd:etcd /var/lib/etcd/default.etcd`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "1.4.12"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'data-dir', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#data-dir'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'

  etcd_process = processes(Regexp.new(%r{/usr/bin/etcd}))
  data_dir = ''

  catch(:stop) do
    if etcd_process.exists?
      if (data_dir = etcd_process.commands.to_s.scan(/--data-dir=(\S+)/).last)
        data_dir = data_dir.first
        throw :stop
      end

      if (data_dir = file("/proc/#{etcd_process.pids.first}/environ").content.split("\0").select { |i| i[/^ETCD_DATA_DIR/] }.first.split('=').last)
        throw :stop
      end
    end
  end

  if !data_dir.empty?
    describe file(data_dir).mode.to_s do
      it { should be_owned_by 'etcd' }
      it { should be_grouped_into 'etcd' }
    end
  else
    describe 'cis-kubernetes-benchmark-1.4.12' do
      skip 'etcd data directory not found'
    end
  end
end
