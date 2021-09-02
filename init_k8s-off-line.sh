# File Name: init_installk8s.sh
# Author: zhangguiyuan
# mail: as953027255@qq.com
# http://1717zgy.com/
# Created Time: Thu 31 Dec 2020 09:30:52 PM CST
# 要开 docker 镜像仓库将 install_docker 函数中注释项取消即可
#!/bin/bash

# 判断系统
OS=`cat /etc/redhat-release | awk -F " " '{print $1}'`
if [[ ${OS} =~ ^[C] ]];then
	echo "系统为 Centos"
else
	exit 10
fi

# 内核判断
K=`uname -r | awk -F "-" '{print $1}'`
if [[ ${K} == 3.10.0 ]];then
	 echo "内核支持"
else
	 exit 10
fi

# 创建本地仓库
YUM(){

rpm -ivh /root/k8sOfflineSetup/packages/deltarpm-3.6-3.el7.x86_64.rpm --nodeps --force
rpm -ivh /root/k8sOfflineSetup/packages/libxml2-python-2.9.1-6.el7.5.x86_64.rpm --nodeps --force
rpm -ivh /root/k8sOfflineSetup/packages/python-deltarpm-3.6-3.el7.x86_64.rpm --nodeps --force
rpm -ivh /root/k8sOfflineSetup/packages/createrepo-0.9.9-28.el7.noarch.rpm --nodeps --force

if [ -f "/etc/yum.repos.d/CentOS-Base.repo" ];then
    mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo_bak_$(date "+%Y-%m-%d_%H-%M-%S")
fi

createrepo  /root/k8sOfflineSetup/packages

cat > /etc/yum.repos.d/CentOS-Media.repo << EOF
# CentOS-Media.repo
#
#  This repo can be used with mounted DVD media, verify the mount point for
#  CentOS-7.  You can use this repo and yum to install items directly off the
#  DVD ISO that we release.
#
# To use this repo, put in your DVD and use it with the other repos too:
#  yum --enablerepo=c7-media [command]
#  
# or for ONLY the media repo, do this:
#
#  yum --disablerepo=\* --enablerepo=c7-media [command]

[c7-media]
name=CentOS-$releasever - Media
baseurl=file:///root/k8sOfflineSetup/packages/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-7
       file:///root/k8sOfflineSetup/gpg/Docker.gpg
       file:///root/k8sOfflineSetup/gpg/Aliyun-kubernetes-yum-key.gpg
       file:///root/k8sOfflineSetup/gpg/Aliyun-kubernetes-rpm-package-key.gpg
EOF

}

# 常用命令下载
CMD(){
yum install -y yum-utils nfs-utils device-mapper-persistent-data lvm2 chrony bash-completion wget lrzsz
}

# 修改主机命令提示
PS(){

cat > /etc/profile.d/env.sh << EOF
PS1="\[\e[1;32m\][\[\e[0m\]\t \[\e[1;33m\]\u\[\e[36m\]@\h\[\e[1;31m\] \W\[\e[1;32m\]]\[\e[0m\]\\\\$"
HISTTIMEFORMAT="%F %T"
HISTCONTROL=ignoreboth
EOF
}

# 调整时间和设置主机名
TIME(){
read -p "please input hostname:" name
hostnamectl set-hostname $name

timedatectl set-timezone Asia/Shanghai
timedatectl set-local-rtc 0
systemctl restart rsyslog

}

# 禁用 swap
SWAP(){
swapoff -a && sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
}


# 调整内核参数针对 K8S
K8S_conf(){

	cat > /etc/sysctl.d/kubernetes.conf << EOF
net.bridge.bridge-nf-call-iptables=1    #开启网桥模式
net.bridge.bridge-nf-call-ip6tables=1   #开启网桥模式
net.ipv4.ip_forward=1
net.ipv4.tcp_tw_recycle=0
vm.swappiness=0 # 禁止使用 swap 空间，只有当系统 OOM 时才允许使用它
vm.overcommit_memory=1 # 不检查物理内存是否够用
vm.panic_on_oom=0 # 开启 OOM  
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
fs.file-max=52706963
fs.nr_open=52706963
net.ipv6.conf.all.disable_ipv6=1    #关闭IPV6的协议
net.netfilter.nf_conntrack_max=2310720
EOF

sysctl -p /etc/sysctl.d/kubernetes.conf 
}

# 关闭防火墙selinux
SELinux(){

	systemctl stop firewalld && systemctl disable firewalld
	sed -i 's#SELINUX=enforcing#SELINUX=disabled#g' /etc/selinux/config
	setenforce 0

}

# 安装 docker
install_docker(){
IP=`ip a |grep eth0 | sed -rn "2s/[^0-9]*([0-9.]+).*/\1/p"`

yum install -y docker-ce-19.03.5 docker-ce-cli-19.03.5 containerd.io

systemctl enable --now docker


# 如需要安装docker 自带仓库取消下列注释即可
# docker run -d -v /opt/registry:/var/lib/registry -p 5000:5000 --restart=always registry

# Conf=/etc/docker
# if [ -d ${Conf} ];then
# cat > /etc/docker/daemon.json << EOF
# {
#       "insecure-registries":["$IP:5000"]                                                                              
# }
# EOF

# else
# mkdir -p ${Conf} && cat > /etc/docker/daemon.json << EOF
# {
#       "insecure-registries":["$IP:5000"]                                                                              
# }
# EOF
# fi
# systemctl daemon-reload 
# systemctl enable --now docker

}

# 安装 k8s
k8s_install(){

yum install  kubeadm-1.15.5-0 kubelet-1.15.5-0 kubectl-1.15.5-0 -y 
systemctl enable kubelet && systemctl start kubelet
docker load < /root/k8sOfflineSetup/images/k8s-images.tar # 将离线镜像指定放到 root 目录下

kubeadm init --apiserver-advertise-address=$IP  --apiserver-bind-port=6443 --kubernetes-version=v1.15.5 --pod-network-cidr=10.233.0.0/16 --service-cidr=172.30.0.0/16 --ignore-preflight-errors=swap
	mkdir -p $HOME/.kube
	sudo cp -f /etc/kubernetes/admin.conf $HOME/.kube/config
	sudo chown $(id -u):$(id -g) $HOME/.kube/config

}

# 安装网络插件
install_CNI() {
cat > calico-etcd.yaml << EOF
---
  # Source: calico/templates/calico-etcd-secrets.yaml
# The following contains k8s Secrets for use with a TLS enabled etcd cluster.
# For information on populating Secrets, see http://kubernetes.io/docs/user-guide/secrets/
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: calico-etcd-secrets
  namespace: kube-system
data:
  # Populate the following with etcd TLS configuration if desired, but leave blank if
  # not using TLS for etcd.
  # The keys below should be uncommented and the values populated with the base64
  # encoded contents of each file that would be associated with the TLS data.
  # Example command for encoding a file contents: cat <file> | base64 -w 0
  etcd-key: LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVBbE9DMTd1cW8wckYrUHlvUUtWOGgyRkF4Y29qeWRvZjMzbnVoZC80bzBTam5xU1UwClRhYjNDOXc1Q0xkZFZoYWFCdm51SFpJZmFGejRjVGxmcFBWR1FUQ2dPYk5rM2tkclFQS20wbDg3eEVxVzZKVEQKQXpNbkdKZmhLKzVtSU1tdENQODhhNmZIZEFieit2OTNRUEF4dEVwUWRYakhnck5FVFNOVHUyeGZMZ3YrU1p6WQpHVEtSYkZKcGpNSzZ2UzZLRm1OUG11RjVjbU9VdG8yMEpuSUJhRWhrbGZaL3F2VGFod1c0TFlhR2NjRFNldTg1Cnk5RFpXd3JOMFpra0xWQ2JCMTRlZ3o1N3RTbE56MEtuWXBxT2Yvemhqck9nVnVkdTQ3WHd6MFBqSHFHbWVBS0wKUkVRaGVYdHd3VDRyMXFUZlhRMks1cnQvMGdmM3hpeTdEcHJnOFFJREFRQUJBb0lCQUNrVXFKODRtVVVxUFEvbwo1M1RERDIvRkVSL3RzaG9MQXRhZGZyekJvVG0xODlhMHNXNEwrSGVKV1NPU2xXcS82ZGlxOW8ycVdJaFB2eTVmCkNvbFdOUUNnRGxaZHJpTzN5Vnl1bUdITWJZMklsNE91S1BHbEY5Q3RlRERMSTl0QVMwTUVTd1BaMUN1c0QzN2YKSjJULzRuZEJXbHBQN1oyZkllVzNMYysxNDcyc25jcjBVK3VIMzg1UVlON3JIS3VVOFNibVBDK2Ntb3VpeTEwVAp1b0RZS3VvYWNSMEs3azZFam85dVM4ejNYSVY4TWw2NjlRSnkzRHlSWUx6MWRYWVFCdnJ6eXhQb3dOWmI2Y1EvCmc1UlpsNmJORXA0RHBydGlQLy9Fd3FORTFnTzh2S1lCc3lQVUhZR0xBZWRXQnlrd0pudmF5Sk9EbE5ZWWx4NS8KTjdFcnhGRUNnWUVBd1BoUGY0Q2ZJVERDY3R6V2xWeEV5VVhGSkhKK0pPbC9QUm4xSWRTR2lxclFYUCtTYVJobgp2SHFNMWQ3TEZzK2JrY2s2Q09uSjcwb2h0RnQvM2JFRGJOWkFIS2JHd3lzcE9qL3BkWXRlVGFVWnNGUE1INVpRCkpCaXZMWjE3UHAwa2d6TFA0bERUSXRlWWFVWXdDT3JTeDlMczhmRGY5b09kUkQrU0N6ejBNT01DZ1lFQXhZR0UKTExiQ2dMeHYrM1FnaDVXTkd0bXZ2RFEySFB1SnMwbnYxZ2p6RGhETkYwZWdIcGU0WFFQM1pQTjNFYTVkeENLWgpPTmpiRElCK3J1clQ0RHB0QzV2UXZoWHhyZ1Q2ZUFLQk94S1B0OUZkUVVTT0ZRSmYrb2NDYk1qc0lNbnQ3YmlmClRuRnhGc21oUzd5Z3BVZzk2Ty82SksxdXN1YlVnL2xaYkptWnN4c0NnWUFQNUNMLzJBTEN3L1l2YVZwT2dJTzEKbzRaQm95QWFRQlJYWHN6ZUZWZGpFZ0FJdUk5QkVsNXdtaE1CQmREcHR2MFR1Mk9KR2wrajBoSUdmVWFCWmpObgpBaG5UZ2pSNkhCTFFGalZPbGNTVlZsUlFQZ1pnVDR1WC9XUm51RUZPL2JmbENna3VsUU5lS2kwRjlsNjhUVUpBCmJIRlExMHBLVGJwa3hXdHNlMytNaXdLQmdCU0ZIVTlyK1k5WWhLWHliY0xJZGUyWk9sbnFic2phRlhkc01oL2gKdENiODllSDZUaGQvbWVjSUYzY0VtSlZjc1Y5RVhQajhCdDRvcDREUzR3cUQ1M3B5U09ERzlPSW9vRUZCdVYyQwoweTI4OGR4ckcvdncwRG4rTnZGSWVzZjVVdUFFODRBNTV3OEFDZU1OaVA5REh6T0pZMHJXUGc4V1RuUWJ2dis2CmdhNkxBb0dBQnlJOWxlbFcxd0FIWXpHdTNRRTVwbHE5UDl6SXlyd2VrM3VCRFB0Q2haMEUxWWhuZ2RiMklzT0wKRGlJT1NyMkVlaXB2a2hkTENEL05mc2luVmNQdzdOb3lvM1pxQ1Q2MUxXQ2Vvbk1IRFVmSHlEaU5leXAzOTl6dApCdnc3clBQVW5VTkh6VnVVaGhVNVpDdnZXVDBLWEFxZ21jWXZRRS9zYVEyVmliZEVJdk09Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==
  etcd-cert: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURNRENDQWhpZ0F3SUJBZ0lJSGQzelBrUEYvNTB3RFFZSktvWklodmNOQVFFTEJRQXdFakVRTUE0R0ExVUUKQXhNSFpYUmpaQzFqWVRBZUZ3MHlNVEF4TURRd05qUXpNVEphRncweU1qQXhNRFF3TmpRek1USmFNQ0F4SGpBYwpCZ05WQkFNVEZXeHZZMkZzYUc5emRDNXNiMk5oYkdSdmJXRnBiakNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFECmdnRVBBRENDQVFvQ2dnRUJBSlRndGU3cXFOS3hmajhxRUNsZklkaFFNWEtJOG5hSDk5NTdvWGYrS05FbzU2a2wKTkUybTl3dmNPUWkzWFZZV21nYjU3aDJTSDJoYytIRTVYNlQxUmtFd29EbXpaTjVIYTBEeXB0SmZPOFJLbHVpVQp3d016SnhpWDRTdnVaaURKclFqL1BHdW54M1FHOC9yL2QwRHdNYlJLVUhWNHg0S3pSRTBqVTd0c1h5NEwva21jCjJCa3lrV3hTYVl6Q3VyMHVpaFpqVDVyaGVYSmpsTGFOdENaeUFXaElaSlgyZjZyMDJvY0Z1QzJHaG5IQTBucnYKT2N2UTJWc0t6ZEdaSkMxUW13ZGVIb00rZTdVcFRjOUNwMktham4vODRZNnpvRmJuYnVPMThNOUQ0eDZocG5nQwppMFJFSVhsN2NNRStLOWFrMzEwTml1YTdmOUlIOThZc3V3NmE0UEVDQXdFQUFhTjhNSG93RGdZRFZSMFBBUUgvCkJBUURBZ1dnTUIwR0ExVWRKUVFXTUJRR0NDc0dBUVVGQndNQkJnZ3JCZ0VGQlFjREFqQkpCZ05WSFJFRVFqQkEKZ2hWc2IyTmhiR2h2YzNRdWJHOWpZV3hrYjIxaGFXNkNDV3h2WTJGc2FHOXpkSWNFd0tnQlNZY0Vmd0FBQVljUQpBQUFBQUFBQUFBQUFBQUFBQUFBQUFUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFybkJpRWk5ZGgyVzRRUTB0ClljK3hNNFdhVStBR2o4dmo2Qi80UkdRc2Z5NmVXNkNYVEFtc0J6TUdEUFd5aUJ2c3J0dGh2bGQ3WkozOHc3TGwKM3RXZ2NaSzJuVHJWajcwdThUZllIOVRWY3VIVHc4RmZLWWlXcnJHZzNPK2NMNG9tOTErL29LQUVVU0RWSlB3SwpHSGtvSDd2VHBlUCtpRzd0TzBVbXRqQjRUUFZOL3I0czB2OU9kSkZ0UEJTVDg4T1JSczIxRzVya05HR2trcUhHCjk3c0puenZrVTFoaUlyOWh2c3ozcnZGbVNEZWxER200eDRXUnFaRVFkU1d1WGVveHNqb0tPZzBYOWtpdS82TXgKb3RqbHhDcHJaNUg1WTExUnZOdzNIZERYQWwrcmFmZGdWcG5NODlZQzFJd2dnblAxNXB5NnAxcGxxM3BWeEh6cAorK2JVSkE9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
  etcd-ca: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUN3akNDQWFxZ0F3SUJBZ0lCQURBTkJna3Foa2lHOXcwQkFRc0ZBREFTTVJBd0RnWURWUVFERXdkbGRHTmsKTFdOaE1CNFhEVEl4TURFd05EQTJORE14TWxvWERUTXhNREV3TWpBMk5ETXhNbG93RWpFUU1BNEdBMVVFQXhNSApaWFJqWkMxallUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU85WDIySVpIMjZqCnJwaGVkOVUwVXkrbUtiODB2b2FFeUR3cCtSeWVFc0xwL1ZFR1lPcVNSckQxelVmMkNPTFpyUXhtTm1vK0Z3anMKYjF6cU5EYjNJOU56N2JwTGFTNWJhTVFiY1A2QlRMWFB2VVpmN3JrQUtBdlFSbnBaUFh0ckpnOFVJamNEMzFDbgpHZ0NUbGRHSEMxSnhIZXkvcjFSaE5wTUVXbk9NUEZJbVp0WXQ2V1dFbythTWxKbVBwRktaSzcvbEdnRmRQRlFjCjNxWTJBb3drTnViMlFSaXJIek8ySWx6SjJmc1ZEUUNMOU1QdVp3VkwxZXVpNmNIR1orSzVSaWp5SjlvcG0xL1gKdEc1bTZKK0pQL1M1Sjl5QmpRWS9aRDJFeENROVJBTVJwb3RLdVRlRGZKb1JTRGpGZFZIM3hKUjY3UXNlbS9hSApIQStjWUtJNEhoTUNBd0VBQWFNak1DRXdEZ1lEVlIwUEFRSC9CQVFEQWdLa01BOEdBMVVkRXdFQi93UUZNQU1CCkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBRWdkSlFZRlFSVjc5R0ZGZFB5ajVVQnBkOXFlUjhiY0t6aWoKVzFNWThQQUJGU1JTcDhCaUljUFNrSG00QU01anpMdm5Rb2t1VGVZbkF0WGdDMm5aekkrVEpLckgwbGJEQ28wQgptY0llTlRyanJqb0hFRDVOTzN0aEdjOFVYWlhOUkFwUjV6K0lBa2NQMjNzdXNvUTJXSnBIKzNVL0dSMDhWeVFtCk85a3RLQ0dVdE5oVGhsMEhtSnBVbFBnT3pnT0czcEpWVWx6NDhvZGZ3bXk4NHVFV0wrbWNrU0pIdFpQQkt6SkwKVzR1a2hsV3VkZmNiYTNTM2JPRVY3MWxLTlhPMTdQZjFaWDVwcCtiYzZnalBnTFhvc0c4SGd1cjlPTjUrLzczbAplK21UMXF0aEVuVEI3WFNHYW8wWFNUTVRuU2NkZzRHdlRQNVhDSERYMHJYNThlbjFwdG89Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
---
# Source: calico/templates/calico-config.yaml
# This ConfigMap is used to configure a self-hosted Calico installation.
kind: ConfigMap
apiVersion: v1
metadata:
  name: calico-config
  namespace: kube-system
data:
  # Configure this with the location of your etcd cluster.
  etcd_endpoints: "https://192.168.1.73:2379"
  # If you're using TLS enabled etcd uncomment the following.
  # You must also populate the Secret below with these files.
  etcd_ca: "/calico-secrets/etcd-ca"
  etcd_cert: "/calico-secrets/etcd-cert"
  etcd_key: "/calico-secrets/etcd-key"
  # Typha is disabled.
  typha_service_name: "none"
  # Configure the backend to use.
  calico_backend: "bird"

  # Configure the MTU to use
  veth_mtu: "1440"

  # The CNI network configuration to install on each node.  The special
  # values in this config will be automatically populated.
  cni_network_config: |-
    {
      "name": "k8s-pod-network",
      "cniVersion": "0.3.1",
      "plugins": [
        {
          "type": "calico",
          "log_level": "info",
          "etcd_endpoints": "__ETCD_ENDPOINTS__",
          "etcd_key_file": "__ETCD_KEY_FILE__",
          "etcd_cert_file": "__ETCD_CERT_FILE__",
          "etcd_ca_cert_file": "__ETCD_CA_CERT_FILE__",
          "mtu": __CNI_MTU__,
          "ipam": {
              "type": "calico-ipam"
          },
          "policy": {
              "type": "k8s"
          },
          "kubernetes": {
              "kubeconfig": "__KUBECONFIG_FILEPATH__"
          }
        },
        {
          "type": "portmap",
          "snat": true,
          "capabilities": {"portMappings": true}
        }
      ]
    }

---
# Source: calico/templates/rbac.yaml

# Include a clusterrole for the kube-controllers component,
# and bind it to the calico-kube-controllers serviceaccount.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: calico-kube-controllers
rules:
  # Pods are monitored for changing labels.
  # The node controller monitors Kubernetes nodes.
  # Namespace and serviceaccount labels are used for policy.
  - apiGroups: [""]
    resources:
      - pods
      - nodes
      - namespaces
      - serviceaccounts
    verbs:
      - watch
      - list
  # Watch for changes to Kubernetes NetworkPolicies.
  - apiGroups: ["networking.k8s.io"]
    resources:
      - networkpolicies
    verbs:
      - watch
      - list
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: calico-kube-controllers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: calico-kube-controllers
subjects:
- kind: ServiceAccount
  name: calico-kube-controllers
  namespace: kube-system
---
# Include a clusterrole for the calico-node DaemonSet,
# and bind it to the calico-node serviceaccount.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: calico-node
rules:
  # The CNI plugin needs to get pods, nodes, and namespaces.
  - apiGroups: [""]
    resources:
      - pods
      - nodes
      - namespaces
    verbs:
      - get
  - apiGroups: [""]
    resources:
      - endpoints
      - services
    verbs:
      # Used to discover service IPs for advertisement.
      - watch
      - list
  - apiGroups: [""]
    resources:
      - nodes/status
    verbs:
      # Needed for clearing NodeNetworkUnavailable flag.
      - patch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: calico-node
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: calico-node
subjects:
- kind: ServiceAccount
  name: calico-node
  namespace: kube-system

---
# Source: calico/templates/calico-node.yaml
# This manifest installs the calico-node container, as well
# as the CNI plugins and network config on
# each master and worker node in a Kubernetes cluster.
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: calico-node
  namespace: kube-system
  labels:
    k8s-app: calico-node
spec:
  selector:
    matchLabels:
      k8s-app: calico-node
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 1
  template:
    metadata:
      labels:
        k8s-app: calico-node
      annotations:
        # This, along with the CriticalAddonsOnly toleration below,
        # marks the pod as a critical add-on, ensuring it gets
        # priority scheduling and that its resources are reserved
        # if it ever gets evicted.
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      nodeSelector:
        beta.kubernetes.io/os: linux
      hostNetwork: true
      tolerations:
        # Make sure calico-node gets scheduled on all nodes.
        - effect: NoSchedule
          operator: Exists
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
        - effect: NoExecute
          operator: Exists
      serviceAccountName: calico-node
      # Minimize downtime during a rolling upgrade or deletion; tell Kubernetes to do a "force
      # deletion": https://kubernetes.io/docs/concepts/workloads/pods/pod/#termination-of-pods.
      terminationGracePeriodSeconds: 0
      priorityClassName: system-node-critical
      initContainers:
        # This container installs the CNI binaries
        # and CNI network config file on each node.
        - name: install-cni
          image: calico/cni:v3.9.6
          imagePullPolicy: IfNotPresent
          command: ["/install-cni.sh"]
          env:
            # Name of the CNI config file to create.
            - name: CNI_CONF_NAME
              value: "10-calico.conflist"
            # The CNI network config to install on each node.
            - name: CNI_NETWORK_CONFIG
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: cni_network_config
            # The location of the etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # CNI MTU Config variable
            - name: CNI_MTU
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: veth_mtu
            # Prevents the container from sleeping forever.
            - name: SLEEP
              value: "false"
          volumeMounts:
            - mountPath: /host/opt/cni/bin
              name: cni-bin-dir
            - mountPath: /host/etc/cni/net.d
              name: cni-net-dir
            - mountPath: /calico-secrets
              name: etcd-certs
        # Adds a Flex Volume Driver that creates a per-pod Unix Domain Socket to allow Dikastes
        # to communicate with Felix over the Policy Sync API.
        - name: flexvol-driver
          image: calico/pod2daemon-flexvol:v3.9.6
          imagePullPolicy: IfNotPresent
          volumeMounts:
          - name: flexvol-driver-host
            mountPath: /host/driver
      containers:
        # Runs calico-node container on each Kubernetes node.  This
        # container programs network policy and routes on each
        # host.
        - name: calico-node
          image: calico/node:v3.9.6
          imagePullPolicy: IfNotPresent
          env:
            # The location of the etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Location of the CA certificate for etcd.
            - name: ETCD_CA_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_ca
            # Location of the client key for etcd.
            - name: ETCD_KEY_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_key
            # Location of the client certificate for etcd.
            - name: ETCD_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_cert
            # Set noderef for node controller.
            - name: CALICO_K8S_NODE_REF
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            # Choose the backend to use.
            - name: CALICO_NETWORKING_BACKEND
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: calico_backend
            # Cluster type to identify the deployment type
            - name: CLUSTER_TYPE
              value: "k8s,bgp"
            # Auto-detect the BGP IP address.
            - name: IP
              value: "autodetect"
            - name: IP_AUTODETECTION_METHOD
              value: "interface=eth0"
            # Enable IPIP
            - name: CALICO_IPV4POOL_IPIP
              value: "Always"
            # Set MTU for tunnel device used if ipip is enabled
            - name: FELIX_IPINIPMTU
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: veth_mtu
            # The default IPv4 pool to create on startup if none exists. Pod IPs will be
            # chosen from this range. Changing this value after installation will have
            # no effect. This should fall within `--cluster-cidr`.
            - name: CALICO_IPV4POOL_CIDR
              value: "10.233.0.0/16"
            # Disable file logging so `kubectl logs` works.
            - name: CALICO_DISABLE_FILE_LOGGING
              value: "true"
            # Set Felix endpoint to host default action to ACCEPT.
            - name: FELIX_DEFAULTENDPOINTTOHOSTACTION
              value: "ACCEPT"
            # Disable IPv6 on Kubernetes.
            - name: FELIX_IPV6SUPPORT
              value: "false"
            # Set Felix logging to "info"
            - name: FELIX_LOGSEVERITYSCREEN
              value: "info"
            - name: FELIX_HEALTHENABLED
              value: "true"
          securityContext:
            privileged: true
          resources:
            requests:
              cpu: 250m
          livenessProbe:
            exec:
              command:
              - /bin/calico-node
              - -felix-live
              - -bird-live
            periodSeconds: 10
            initialDelaySeconds: 10
            failureThreshold: 6
          readinessProbe:
            exec:
              command:
              - /bin/calico-node
              - -felix-ready
              - -bird-ready
            periodSeconds: 10
          volumeMounts:
            - mountPath: /lib/modules
              name: lib-modules
              readOnly: true
            - mountPath: /run/xtables.lock
              name: xtables-lock
              readOnly: false
            - mountPath: /var/run/calico
              name: var-run-calico
              readOnly: false
            - mountPath: /var/lib/calico
              name: var-lib-calico
              readOnly: false
            - mountPath: /calico-secrets
              name: etcd-certs
            - name: policysync
              mountPath: /var/run/nodeagent
      volumes:
        # Used by calico-node.
        - name: lib-modules
          hostPath:
            path: /lib/modules
        - name: var-run-calico
          hostPath:
            path: /var/run/calico
        - name: var-lib-calico
          hostPath:
            path: /var/lib/calico
        - name: xtables-lock
          hostPath:
            path: /run/xtables.lock
            type: FileOrCreate
        # Used to install CNI.
        - name: cni-bin-dir
          hostPath:
            path: /opt/cni/bin
        - name: cni-net-dir
          hostPath:
            path: /etc/cni/net.d
        # Mount in the etcd TLS secrets with mode 400.
        # See https://kubernetes.io/docs/concepts/configuration/secret/
        - name: etcd-certs
          secret:
            secretName: calico-etcd-secrets
            defaultMode: 0400
        # Used to create per-pod Unix Domain Sockets
        - name: policysync
          hostPath:
            type: DirectoryOrCreate
            path: /var/run/nodeagent
        # Used to install Flex Volume Driver
        - name: flexvol-driver-host
          hostPath:
            type: DirectoryOrCreate
            path: /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds
---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-node
  namespace: kube-system

---
# Source: calico/templates/calico-kube-controllers.yaml

# See https://github.com/projectcalico/kube-controllers
apiVersion: apps/v1
kind: Deployment
metadata:
  name: calico-kube-controllers
  namespace: kube-system
  labels:
    k8s-app: calico-kube-controllers
spec:
  # The controllers can only have a single active instance.
  replicas: 2
  selector:
    matchLabels:
      k8s-app: calico-kube-controllers
  strategy:
    type: Recreate
  template:
    metadata:
      name: calico-kube-controllers
      namespace: kube-system
      labels:
        k8s-app: calico-kube-controllers
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      nodeSelector:
        beta.kubernetes.io/os: linux
      tolerations:
        # Mark the pod as a critical add-on for rescheduling.
        - key: CriticalAddonsOnly
          operator: Exists
        - key: node-role.kubernetes.io/master
          effect: NoSchedule
      serviceAccountName: calico-kube-controllers
      priorityClassName: system-cluster-critical
      # The controllers must run in the host network namespace so that
      # it isn't governed by policy that would prevent it from working.
      hostNetwork: true
      containers:
        - name: calico-kube-controllers
          image: calico/kube-controllers:v3.9.6
          imagePullPolicy: IfNotPresent
          env:
            # The location of the etcd cluster.
            - name: ETCD_ENDPOINTS
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_endpoints
            # Location of the CA certificate for etcd.
            - name: ETCD_CA_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_ca
            # Location of the client key for etcd.
            - name: ETCD_KEY_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_key
            # Location of the client certificate for etcd.
            - name: ETCD_CERT_FILE
              valueFrom:
                configMapKeyRef:
                  name: calico-config
                  key: etcd_cert
            # Choose which controllers to run.
            - name: ENABLED_CONTROLLERS
              value: policy,namespace,serviceaccount,workloadendpoint,node
          volumeMounts:
            # Mount in the etcd TLS secrets.
            - mountPath: /calico-secrets
              name: etcd-certs
          readinessProbe:
            exec:
              command:
              - /usr/bin/check-status
              - -r
      volumes:
        # Mount in the etcd TLS secrets with mode 400.
        # See https://kubernetes.io/docs/concepts/configuration/secret/
        - name: etcd-certs
          secret:
            secretName: calico-etcd-secrets
            defaultMode: 0400

---

apiVersion: v1
kind: ServiceAccount
metadata:
  name: calico-kube-controllers
  namespace: kube-system
---
# Source: calico/templates/calico-typha.yaml

---
# Source: calico/templates/configure-canal.yaml

---
# Source: calico/templates/kdd-crds.yaml
EOF
  #curl https://docs.projectcalico.org/v3.9/manifests/calico-etcd.yaml -O  && echo "calico文件下载完成"

  POD_CIDR=`grep 'cluster-cidr' /etc/kubernetes/manifests/kube-controller-manager.yaml | awk -F= '{print $2}'`
 
  sed '/CALICO_IPV4POOL_CIDR/{n;s#".*"#"'$POD_CIDR'"#}' calico-etcd.yaml -i

  sed -i 's/# \(etcd-.*\)/\1/' calico-etcd.yaml
  etcd_key=$(cat /etc/kubernetes/pki/etcd/peer.key | base64 -w 0)
  etcd_crt=$(cat /etc/kubernetes/pki/etcd/peer.crt | base64 -w 0)
  etcd_ca=$(cat /etc/kubernetes/pki/etcd/ca.crt | base64 -w 0)
  sed -i -e 's/\(etcd-key: \).*/\1'$etcd_key'/' \
     -e 's/\(etcd-cert: \).*/\1'$etcd_crt'/' \
     -e 's/\(etcd-ca: \).*/\1'$etcd_ca'/' calico-etcd.yaml

  ETCD=$(grep 'advertise-client-urls' /etc/kubernetes/manifests/etcd.yaml | awk -F= '{print $2}')
  sed -i -e 's@\(etcd_endpoints: \).*@\1"'$ETCD'"@' \
     -e 's/\(etcd_.*:\).*#/\1/' \
     -e 's/replicas: 1/replicas: 2/' calico-etcd.yaml

   sed '/autodetect/a\            - name: IP_AUTODETECTION_METHOD\n              value: "interface=eth0"' -i calico-etcd.yaml  && \
	kubectl apply -f calico-etcd.yaml && \
	echo "***********\nCNI 已安装"
}

# node 节点安装
k8sNode(){
yum install  kubeadm-1.15.5-0 kubelet-1.15.5-0 kubectl-1.15.5-0 -y 
systemctl enable kubelet && systemctl start kubelet

docker load < /root/k8sOfflineSetup/images/k8s-images.tar

}

source /usr/share/bash-completion/bash_completion
source <(kubectl completion bash)
echo 'source <(kubectl completion bash)' >> ~/.bashrc

YUM
CMD
PS
TIME
SWAP
K8S_conf
SELinux
install_docker

# node 节点注释下面两个函数
k8s_install
install_CNI

# master 节点注释下面这个函数
#k8sNode
