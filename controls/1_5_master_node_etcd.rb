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

title '1.5 Master Node: etcd'

etcd_regex = Regexp.new(%r{/usr/bin/etcd})
etcd_process = processes(etcd_regex)
etcd_env_vars = process_env_var(etcd_regex)

only_if do
  etcd_process.exists?
end

control 'cis-kubernetes-benchmark-1.5.1' do
  title 'Ensure that the --cert-file and --key-file arguments are set as appropriate (Scored)'
  desc "Configure TLS encryption for the etcd service."
  impact 1.0

  tag rationale: "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be encrypted in transit."

  tag check: "Run the following command on the etcd server node

  `ps -ef | grep etcd`

  Verify that the `--cert-file` and the `--key-file` arguments are set as appropriate."

  tag fix: ""

  tag cis_family: ['14.2', '6.1']
  tag cis_rid: "1.5.1"
  tag cis_level: 1
  tag nist: ['', '4']

  ref 'security.html', url: 'https://coreos.com/etcd/docs/latest/op-guide/security.html'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'

  describe.one do
    describe etcd_process.commands.to_s do
      it { should match(/--cert-file=/) }
    end

    describe etcd_env_vars do
      its(:ETCD_CERT_FILE) { should_not be_empty }
    end
  end

  describe.one do
    describe etcd_process.commands.to_s do
      it { should match(/--key-file=/) }
    end

    describe etcd_env_vars do
      its(:ETCD_KEY_FILE) { should_not be_empty }
    end
  end
end

control 'cis-kubernetes-benchmark-1.5.2' do
  title 'Ensure that the --client-cert-auth argument is set to true (Scored)'
  desc "Enable client authentication on etcd service."
  impact 1.0

  tag rationale: "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should not be available to unauthenticated clients. You should enable the client authentication via valid certificates to secure the access to the etcd service."

  tag check: "Run the following command on the etcd server node:

  `ps -ef | grep etcd`

  Verify that the `--client-cert-auth` argument is set to `true`."

  tag fix: "Edit the etcd envrironment file (for example, `/etc/etcd/etcd.conf`) on the etcd server node and set the `ETCD_CLIENT_CERT_AUTH` parameter to `\"true\"`:

  `ETCD_CLIENT_CERT_AUTH=\"true\"`

  Edit the etcd startup file (for example, `/etc/systemd/system/multi- user.target.wants/etcd.service`) and configure the startup parameter for `--client-cert-auth` and set it to `\"${ETCD_CLIENT_CERT_AUTH}\"`:

  `ExecStart=/bin/bash -c \"GOMAXPROCS=$(nproc) /usr/bin/etcd --name=\"${ETCD_NAME}\" --data-dir=\"${ETCD_DATA_DIR}\" --listen-client- urls=\"${ETCD_LISTEN_CLIENT_URLS}\" --client-cert- auth=\"${ETCD_CLIENT_CERT_AUTH}\"\"`

  Based on your system, reload the daemon and restart the `etcd` service. For example,

  `systemctl daemon-reload
  systemctl restart etcd.service`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "1.5.2"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'security.html', url: 'https://coreos.com/etcd/docs/latest/op-guide/security.html'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'
  ref 'client-cert-auth', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#client-cert-auth'

  describe.one do
    describe etcd_process.commands.to_s do
      it { should match(/--client-cert-auth=true/) }
    end

    describe etcd_env_vars do
      its(:ETCD_CLIENT_CERT_AUTH) { should_not be_empty }
    end
  end
end

control 'cis-kubernetes-benchmark-1.5.3' do
  title 'Ensure that the --auto-tls argument is not set to true (Scored)'
  desc "Do not use self-signed certificates for TLS."
  impact 1.0

  tag rationale: "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should not be available to unauthenticated clients. You should enable the client authentication via valid certificates to secure the access to the etcd service."

  tag check: "Run the following command on the etcd server node:

  `ps -ef | grep etcd`

  Verify that if the `--auto-tls` argument exists, it is not set to `true`."

  tag fix: "Edit the etcd environment file (for example, `/etc/etcd/etcd.conf`) on the etcd server node and comment out the `ETCD_AUTO_TLS` parameter.

  `#ETCD_AUTO_TLS=\"true\"`

  Edit the etcd startup file (for example, `/etc/systemd/system/multi-user.target.wants/etcd.service`) and remove the startup parameter for `--auto-tls`. Based on your system, reload the daemon and restart the `etcd` service. For example,

  `systemctl daemon-reload
  systemctl restart etcd.service`"

  tag cis_family: ['14.2', '6.1']
  tag cis_rid: "1.5.3"
  tag cis_level: 1
  tag nist: ['', '4']

  ref 'security.html', url: 'https://coreos.com/etcd/docs/latest/op-guide/security.html'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'
  ref 'auto-tls', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#auto-tls'

  describe etcd_process.commands.to_s do
    it { should_not match(/--auto-tls=true/) }
  end
end

control 'cis-kubernetes-benchmark-1.5.4' do
  title 'Ensure that the --peer-cert-file and --peer-key-file arguments are set as appropriate (Scored)'
  desc "etcd should be configured to make use of TLS encryption for peer connections."
  impact 1.0

  tag rationale: "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be encrypted in transit and also amongst peers in the etcd clusters."

  tag check: "Run the following command on the etcd server node:

  `ps -ef | grep etcd`

  Verify that the `--peer-cert-file` and `--peer-key-file` arguments are set as appropriate.

  Note: This recommendation is applicable only for etcd clusters. If you are using only one etcd server in your environment then this recommendation is not applicable."

  tag fix: "Follow the etcd service documentation and configure peer TLS encryption as appropriate for your etcd cluster."

  tag cis_family: ['14.2', '6.1']
  tag cis_rid: "1.5.4"
  tag cis_level: 1
  tag nist: ['', '4']

  ref 'security.html', url: 'https://coreos.com/etcd/docs/latest/op-guide/security.html'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'

  describe.one do
    describe etcd_process.commands.to_s do
      it { should match(/--peer-cert-file=/) }
    end

    describe etcd_env_vars do
      its(:ETCD_PEER_CERT_FILE) { should_not be_empty }
    end
  end

  describe.one do
    describe etcd_process.commands.to_s do
      it { should match(/--peer-key-file=/) }
    end

    describe etcd_env_vars do
      its(:ETCD_PEER_KEY_FILE) { should_not be_empty }
    end
  end
end

control 'cis-kubernetes-benchmark-1.5.5' do
  title 'Ensure that the --peer-client-cert-auth argument is set to true (Scored)'
  desc "etcd should be configured for peer authentication."
  impact 1.0

  tag rationale: "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster."

  tag check: "Run the following command on the etcd server node:

  `ps -ef | grep etcd`

  Verify that the `--peer-client-cert-auth` argument is set to `true`.

  Note: This recommendation is applicable only for etcd clusters. If you are using only one
  etcd server in your environment then this recommendation is not applicable."

  tag fix: "Edit the etcd environment file (for example, `/etc/etcd/etcd.conf`) on the etcd server node and set the `ETCD_PEER_CLIENT_CERT_AUTH` parameter to `\"true\"`:

  `ETCD_PEER_CLIENT_CERT_AUTH=\"true\"`

  Edit the etcd startup file (for example, `/etc/systemd/system/multi-user.target.wants/etcd.service`) and configure the startup parameter for `--peer- client-cert-auth` and set it to `\"${ETCD_PEER_CLIENT_CERT_AUTH}\"`:

  `ExecStart=/bin/bash -c \"GOMAXPROCS=$(nproc) /usr/bin/etcd -- name=\"${ETCD_NAME}\" --data-dir=\"${ETCD_DATA_DIR}\"--listen-client- urls=\"${ETCD_LISTEN_CLIENT_URLS}\" --peer-client-cert- auth=\"${ETCD_PEER_CLIENT_CERT_AUTH}\"\"`

  Based on your system, reload the daemon and restart the etcd service. For example,

  `systemctl daemon-reload
  systemctl restart etcd.service`"

  tag cis_family: ['14.4', '6.1']
  tag cis_rid: "1.5.5"
  tag cis_level: 1
  tag nist: ['', '4']

  ref 'security.html', url: 'https://coreos.com/etcd/docs/latest/op-guide/security.html'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'
  ref 'peer-client-cert-auth', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#peer-client-cert-auth'

  describe.one do
    describe etcd_process.commands.to_s do
      it { should match(/--peer-client-cert-auth=true/) }
    end

    describe etcd_env_vars do
      its(:ETCD_PEER_CLIENT_CERT_AUTH) { should_not be_empty }
    end
  end
end

control 'cis-kubernetes-benchmark-1.5.6' do
  title 'Ensure that the --peer-auto-tls argument is not set to true (Scored)'
  desc "Do not use automatically generated self-signed certificates for TLS connections between peers."
  impact 1.0

  tag rationale: "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should be accessible only by authenticated etcd peers in the etcd cluster. Hence, do not use self-signed certificates for authentication."

  tag check: "Run the following command on the etcd server node:

  `ps -ef | grep etcd`

  Verify that if the `--peer-auto-tls` argument exists, it is not set to `true`. Note: This recommendation is applicable only for etcd clusters. If you are using only one etcd server in your environment then this recommendation is not applicable."

  tag fix: "Edit the etcd environment file (for example, `/etc/etcd/etcd.conf`) on the etcd server node and comment out the `ETCD_PEER_AUTO_TLS` parameter:

  `#ETCD_PEER_AUTO_TLS=\"true\"`

  Edit the etcd startup file (for example, `/etc/systemd/system/multi-user.target.wants/etcd.service`) and remove the startup parameter for `--peer-auto- tls`. Based on your system, reload the daemon and restart the etcd service. For example,

  `systemctl daemon-reload
  systemctl restart etcd.service`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "1.5.6"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'security.html', url: 'https://coreos.com/etcd/docs/latest/op-guide/security.html'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'
  ref 'peer-auto-tls', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#peer-auto-tls'

  describe etcd_process.commands.to_s do
    it { should_not match(/--peer-auto-tls=true/) }
  end
end

control 'cis-kubernetes-benchmark-1.5.7' do
  title 'Ensure that the --wal-dir argument is set as appropriate (Scored)'
  desc "Store etcd logs separately from etcd data."
  impact 1.0

  tag rationale: "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. These objects are sensitive in nature and should not be mixed with log data. Keeping the log data separate from the etcd data also ensures that those two types of data could individually be safeguarded. Also, you could use a centralized and remote log directory for persistent logging. Additionally, this separation also helps to avoid IO competition between logging and other IO operations."

  tag check: "Run the following command on the etcd server node:

  `ps -ef | grep etcd`

  Verify that `--wal-dir` argument exists, and it is set as appropriate. At the minimum, it should not be set to the same directory as set for `--data-dir` argument."

  tag fix: "Edit the etcd environment file (for example, `/etc/etcd/etcd.conf`) on the etcd server node and set the `ETCD_WAL_DIR` parameter as appropriate:

  `ETCD_WAL_DIR=\"<dir-name>\"`

  Edit the etcd startup file (for example, `/etc/systemd/system/multi-user.target.wants/etcd.service`) and configure the startup parameter for `--wal-dir` and set it to `\"${ETCD_WAL_DIR}\"`:

  `ExecStart=/bin/bash -c \"GOMAXPROCS=$(nproc) /usr/bin/etcd -- name=\"${ETCD_NAME}\" --data-dir=\"${ETCD_DATA_DIR}\" --listen-client- urls=\"${ETCD_LISTEN_CLIENT_URLS}\" --wal-dir=\"${ETCD_WAL_DIR}\"\"`

  Based on your system, reload the daemon and restart the etcd service. For example,

  `systemctl daemon-reload
  systemctl restart etcd.service`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "1.5.7"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'
  ref 'wal-dir', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#wal-dir'
  ref 'data-dir', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#data-dir'

  wal_dir = ''

  catch(:stop) do
    if etcd_process.exists?
      if (wal_dir = etcd_process.commands.to_s.scan(/--data-dir=(\S+)/).last)
        wal_dir = wal_dir.first
        throw :stop
      end

      if (wal_dir = etcd_env_vars.ETCD_WAL_DIR)
        throw :stop
      end
    end
  end

  if !wal_dir.empty?
    describe file(wal_dir).mode.to_s do
      it { should be_owned_by 'etcd' }
      it { should be_grouped_into 'etcd' }
    end
  else
    describe 'cis-kubernetes-benchmark-1.5.7' do
      skip 'WAL directory not found'
    end
  end
end

control 'cis-kubernetes-benchmark-1.5.8' do
  title 'Ensure that the --max-wals argument is set to 0 (Scored)'
  desc "Do not auto rotate logs."
  impact 1.0

  tag rationale: "etcd is a highly-available key value store used by Kubernetes deployments for persistent storage of all of its REST API objects. You should avoid automatic log rotation and instead safeguard the logs in a centralized repository or through a separate log management system."

  tag check: "Run the following command on the etcd server node:

  `ps -ef | grep etcd`

  Verify that `--max-wals` argument exists and it is set to `0`."

  tag fix: "Edit the etcd environment file (for example, `/etc/etcd/etcd.conf`) on the etcd server node and set the `ETCD_MAX_WALS` parameter to `0`:

  `ETCD_MAX_WALS=\"0\"`

  Edit the etcd startup file (for example, `/etc/systemd/system/multi-user.target.wants/etcd.service`) and configure the startup parameter for `--max-wals` and set it to `\"${ETCD_MAX_WALS}\"`:

  `ExecStart=/bin/bash -c \"GOMAXPROCS=$(nproc) /usr/bin/etcd --name=\"${ETCD_NAME}\" --data-dir=\"${ETCD_DATA_DIR}\" --listen-client- urls=\"${ETCD_LISTEN_CLIENT_URLS}\" --max-walsr=\"${ETCD_MAX_WALS}\"\"`

  Based on your system, reload the daemon and restart the etcd service. For example,

  `systemctl daemon-reload
  systemctl restart etcd.service`"

  tag cis_family: ['6', '6.1']
  tag cis_rid: "1.5.8"
  tag cis_level: 1
  tag nist: ['AU-6', '4']

  ref 'max-wals', url: 'https://coreos.com/etcd/docs/latest/op-guide/configuration.html#max-wals'
  ref 'kubernetes-etcd', url: 'https://kubernetes.io/docs/admin/etcd/'

  describe.one do
    describe etcd_process.commands.to_s do
      it { should match(/--max-wals=0/) }
    end

    describe etcd_env_vars do
      its(:ETCD_MAX_WALS) { should eq '0' }
    end
  end
end

if cis_level == '2'
  control 'cis-kubernetes-benchmark-1.5.9' do
    title 'Ensure that a unique Certificate Authority is used for etcd (Not Scored)'
    desc "Use a different certificate authority for etcd from the one used for Kubernetes."
    impact 0.0

    tag rationale: "etcd is a highly available key-value store used by Kubernetes deployments for persistent storage of all of its REST API objects. Its access should be restricted to specifically designated clients and peers only. Authentication to etcd is based on whether the certificate presented was issued by a trusted certificate authority. There is no checking of certificate attributes such as common name or subject alternative name. As such, if any attackers were able to gain access to any certificate issued by the trusted certificate authority, they would be able to gain full access to the etcd database."

    tag check: "Review the CA used by the etcd environment and ensure that it does not match the CA certificate used by Kubernetes.

    Run the following command on the etcd server node:

    `ps -ef | grep etcd`

    Review the file referenced by the `--trusted-ca-file` argument and ensure that the referenced CA is not the same one as is used for management of the overall Kubernetes cluster."

    tag fix: "Follow the etcd documentation and create a dedicated certificate authority setup for the etcd service."

    tag cis_family: ['9', '6.1']
    tag cis_rid: "1.5.9"
    tag cis_level: 2
    tag nist: ['SC-7', '4']

    ref 'security.html', url: 'https://coreos.com/etcd/docs/latest/op-guide/security.html'

    describe 'cis-kubernetes-benchmark-1.5.9' do
      skip 'Review if the CA used for etcd is different from the one used for Kubernetes'
    end
  end
end
