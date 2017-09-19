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

title '1.2 Master Node: Scheduler'

only_if do
  processes('kube-scheduler').exists?
end

control 'cis-kubernetes-benchmark-1.2.1' do
  title 'Ensure that the --profiling argument is set to false (Scored)'
  desc "Disable profiling, if not needed."
  impact 1.0

  tag rationale: "Profiling allows for the identification of specific performance bottlenecks. It generates a significant amount of program data that could potentially be exploited to uncover system and program details. If you are not experiencing any bottlenecks and do not need the profiler for troubleshooting purposes, it is recommended to turn it off to reduce the potential attack surface."

  tag check: "Run the following command on the master node:

  `ps -ef | grep kube-scheduler`

  Verify that the `--profiling` argument is set to `false`."

  tag fix: "Edit the `/etc/kubernetes/scheduler` file on the master node and set the `KUBE_SCHEDULER_ARGS` parameter to `"--profiling=false"`:

  `KUBE_SCHEDULER_ARGS="--profiling=false"`

  Based on your system, restart the `kube-scheduler` service. For example:

  `systemctl restart kube-scheduler.service`"

  tag cis_family: ['14', '6.1']
  tag cis_rid: "1.2.1"
  tag cis_level: 1
  tag nist: ['AC-6', '4']

  ref 'kube-scheduler', url: 'https://kubernetes.io/docs/admin/kube-scheduler/'
  ref 'profiling.md', url: 'https://github.com/kubernetes/community/blob/master/contributors/devel/profi
ling.md'

  describe processes('kube-scheduler').commands.to_s do
    it { should match(/--profiling=false/) }
  end
end
