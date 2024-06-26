{ config, pkgs, ... }:

{
  services.kubelet = {
    enable = true;
    address = "[address]";
    allowed-unsafe-sysctls = [ "sys.*" ];
    anonymous-auth = true;
    application-metrics-count-limit = 1;
    authentication-token-webhook = true;
    authentication-token-webhook-cache-ttl = "[authentication-token-webhook-cache-ttl]";
    authorization-mode = "[authorization-mode]";
    authorization-webhook-cache-authorized-ttl = "[authorization-webhook-cache-authorized-ttl]";
    authorization-webhook-cache-unauthorized-ttl = "[authorization-webhook-cache-unauthorized-ttl]";
    boot-id-file = [ "/proc/sys/kernel/random/boot_id" ];
    bootstrap-kubeconfig = ./kubelet.nix;
    cert-dir = ./.;
    cgroup-driver = "cgroupfs";
    cgroup-root = "[cgroup-root]";
    cgroups-per-qos = false;
    client-ca-file = ./kubelet.nix;
    cloud-config = ./kubelet.nix;
    cloud-provider = "[cloud-provider]";
    cluster-dns = [ "[cluster-dns-1]" "[cluster-dns-2]" ];
    cluster-domain = "[cluster-domain]";
    configFile = ./kubelet.nix;
    config-dir = ./.;
    container-hints = ./kubelet.nix;
    container-log-max-files = 2;
    container-log-max-size = "[container-log-max-size]";
    container-runtime-endpoint = "[container-runtime-endpoint]";
    containerd = ./kubelet.nix;
    containerd-namespace = "[containerd-namespace]";
    contention-profiling = true;
    cpu-cfs-quota = true;
    cpu-cfs-quota-period = "[cpu-cfs-quota-period]";
    cpu-manager-policy = "[cpu-manager-policy]";
    cpu-manager-policy-options = [ "option1" "option2" ];
    cpu-manager-reconcile-period = "[cpu-manager-reconcile-period]";
    enable-controller-attach-detach = true;
    enable-debugging-handlers = true;
    enable-load-reader = "[enable-load-reader]";
    enable-server = "[enable-server]";
    enforce-node-allocatable = [ "none" "pods" "system-reserved" "kube-reserved" ];
    event-burst = 3;
    event-qps = 4;
    event-storage-age-limit = "[event-storage-age-limit]";
    event-storage-event-limit = "[event-storage-event-limit]";
    eviction-hard = [ "[eviction-hard-1]" "[eviction-hard-2]" ];
    eviction-max-pod-grace-period = 5;
    eviction-minimum-reclaim = [ "[eviction-minimum-reclaim-1]" "[eviction-minimum-reclaim-2]" ];
    eviction-pressure-transition-period = "[eviction-pressure-transition-period]";
    eviction-soft = [ "[eviction-soft-1]" "[eviction-soft-2]" ];
    eviction-soft-grace-period = [ "[eviction-soft-grace-period-1]" "[eviction-soft-grace-period-2]" "[eviction-soft-grace-period-3]" ];
    exit-on-lock-contention = true;
    experimental-allocatable-ignore-eviction = true;
    experimental-mounter-path = ./kubelet.nix;
    fail-swap-on = true;
    feature-gates = [
      "APIListChunking=true"
      "APIPriorityAndFairness=true"
      "APIResponseCompression=true"
      "APIServerIdentity=true"
      "APIServerTracing=true"
      "AdmissionWebhookMatchConditions=true"
      "AggregatedDiscoveryEndpoint=true"
      "AllAlpha=true"
      "AllBeta=true"
      "AnyVolumeDataSource=true"
      "AppArmor=true"
      "CPUManagerPolicyAlphaOptions=true"
      "CPUManagerPolicyBetaOptions=true"
      "CPUManagerPolicyOptions=true"
      "CRDValidationRatcheting=true"
      "CSIMigrationPortworx=true"
      "CSINodeExpandSecret=true"
      "CSIVolumeHealth=true"
      "CloudControllerManagerWebhook=true"
      "CloudDualStackNodeIPs=true"
      "ClusterTrustBundle=true"
      "ComponentSLIs=true"
      "ConsistentListFromCache=true"
      "ContainerCheckpoint=true"
      "ContextualLogging=true"
      "CronJobsScheduledAnnotation=true"
      "CrossNamespaceVolumeDataSource=true"
      "CustomCPUCFSQuotaPeriod=true"
      "CustomResourceValidationExpressions=true"
      "DevicePluginCDIDevices=true"
      "DisableCloudProviders=true"
      "DisableKubeletCloudCredentialProviders=true"
      "DynamicResourceAllocation=true"
      "ElasticIndexedJob=true"
      "EventedPLEG=true"
      "GracefulNodeShutdown=true"
      "GracefulNodeShutdownBasedOnPodPriority=true"
      "HPAContainerMetrics=true"
      "HPAScaleToZero=true"
      "HonorPVReclaimPolicy=true"
      "InPlacePodVerticalScaling=true"
      "InTreePluginAWSUnregister=true"
      "InTreePluginAzureDiskUnregister=true"
      "InTreePluginAzureFileUnregister=true"
      "InTreePluginGCEUnregister=true"
      "InTreePluginOpenStackUnregister=true"
      "InTreePluginPortworxUnregister=true"
      "InTreePluginvSphereUnregister=true"
      "JobBackoffLimitPerIndex=true"
      "JobPodFailurePolicy=true"
      "JobPodReplacementPolicy=true"
      "JobReadyPods=true"
      "KMSv2=true"
      "KMSv2KDF=true"
      "KubeProxyDrainingTerminatingNodes=true"
      "KubeletCgroupDriverFromCRI=true"
      "KubeletInUserNamespace=true"
      "KubeletPodResourcesDynamicResources=true"
      "KubeletPodResourcesGet=true"
      "KubeletTracing=true"
      "LegacyServiceAccountTokenCleanUp=true"
      "LocalStorageCapacityIsolationFSQuotaMonitoring=true"
      "LogarithmicScaleDown=true"
      "LoggingAlphaOptions=true"
      "LoggingBetaOptions=true"
      "MatchLabelKeysInPodTopologySpread=true"
      "MaxUnavailableStatefulSet=true"
      "MemoryManager=true"
      "MemoryQoS=true"
      "MinDomainsInPodTopologySpread=true"
      "MultiCIDRRangeAllocator=true"
      "MultiCIDRServiceAllocator=true"
      "NewVolumeManagerReconstruction=true"
      "NodeInclusionPolicyInPodTopologySpread=true"
      "NodeLogQuery=true"
      "NodeSwap=true"
      "OpenAPIEnums=true"
      "PDBUnhealthyPodEvictionPolicy=true"
      "PersistentVolumeLastPhaseTransitionTime=true"
      "PodAndContainerStatsFromCRI=true"
      "PodDeletionCost=true"
      "PodDisruptionConditions=true"
      "PodHostIPs=true"
      "PodIndexLabel=true"
      "PodReadyToStartContainersCondition=true"
      "PodSchedulingReadiness=true"
      "ProcMountType=true"
      "QOSReserved=true"
      "ReadWriteOncePod=true"
      "RecoverVolumeExpansionFailure=true"
      "RemainingItemCount=true"
      "RotateKubeletServerCertificate=true"
      "SELinuxMountReadWriteOncePod=true"
      "SchedulerQueueingHints=true"
      "SecurityContextDeny=true"
      "SeparateCacheWatchRPC=true"
      "ServiceNodePortStaticSubrange=true"
      "SidecarContainers=true"
      "SizeMemoryBackedVolumes=true"
      "SkipReadOnlyValidationGCE=true"
      "StableLoadBalancerNodeSet=true"
      "StatefulSetAutoDeletePVC=true"
      "StatefulSetStartOrdinal=true"
      "StorageVersionAPI=true"
      "StorageVersionHash=true"
      "TopologyAwareHints=true"
      "TopologyManagerPolicyAlphaOptions=true"
      "TopologyManagerPolicyBetaOptions=true"
      "TopologyManagerPolicyOptions=true"
      "UnauthenticatedHTTP2DOSMitigation=true"
      "UnknownVersionInteroperabilityProxy=true"
      "UserNamespacesSupport=true"
      "ValidatingAdmissionPolicy=true"
      "VolumeCapacityPriority=true"
      "WatchFromStorageWithoutResourceVersion=true"
      "WatchList=true"
      "WinDSR=true"
      "WinOverlay=true"
      "WindowsHostNetwork=true"
    ];
    file-check-frequency = "[file-check-frequency]";
    global-housekeeping-interval = "[global-housekeeping-interval]";
    hairpin-mode = "none";
    healthz-bind-address = "[healthz-bind-address]";
    healthz-port = 6;
    hostname-override = "[hostname-override]";
    housekeeping-interval = "[housekeeping-interval]";
    http-check-frequency = "[http-check-frequency]";
    image-credential-provider-bin-dir = ./.;
    image-credential-provider-config = ./kubelet.nix;
    image-gc-high-threshold = 7;
    image-gc-low-threshold = 8;
    image-service-endpoint = "[image-service-endpoint]";
    keep-terminated-pod-volumes = true;
    kernel-memcg-notification = "[kernel-memcg-notification]";
    kube-api-burst = 9;
    kube-api-content-type = "[kube-api-content-type]";
    kube-api-qps = 10;
    kube-reserved = [ "[kube-reserved-1]" "[kube-reserved-2]" ];
    kube-reserved-cgroup = "[kube-reserved-cgroup]";
    kubeconfig = ./kubelet.nix;
    kubelet-cgroups = "[kubelet-cgroups]";
    local-storage-capacity-isolation = true;
    lock-file = ./kubelet.nix;
    log-cadvisor-usage = true;
    log-flush-frequency = "[log-flush-frequency]";
    log-json-info-buffer-size = "[log-json-info-buffer-size]";
    log-json-split-stream = true;
    logging-format = "json";
    machine-id-file = [ ./kubelet.nix ];
    make-iptables-util-chains = true;
    manifest-url = "[manifest-url]";
    manifest-url-header = [ "[manifest-url-header-1]" "[manifest-url-header-2]" ];
    max-open-files = 11;
    max-pods = 12;
    maximum-dead-containers = 13;
    maximum-dead-containers-per-container = 14;
    memory-manager-policy = "None";
    minimum-container-ttl-duration = "[minimum-container-ttl-duration]";
    minimum-image-ttl-duration = "[minimum-image-ttl-duration]";
    node-ip = "[node-ip]";
    node-labels = [ "[node-labels-1]" "[node-labels-2]" ];
    node-status-max-images = 15;
    node-status-update-frequency = "[node-status-update-frequency]";
    oom-score-adj = 16;
    pod-cidr = "[pod-cidr]";
    pod-infra-container-image = "[pod-infra-container-image]";
    pod-manifest-path = ./kubelet.nix;
    pod-max-pids = 17;
    pods-per-core = 18;
    port = 19;
    protect-kernel-defaults = true;
    provider-id = "[provider-id]";
    qos-reserved = [ "[qos-reserved-1]" "[qos-reserved-2]" "[qos-reserved-3]" ];
    read-only-port = 20;
    register-node = true;
    register-schedulable = true;
    register-with-taints = [ "[register-with-taints-1]" "[register-with-taints-2]" ];
    registry-burst = 21;
    registry-qps = 22;
    reserved-cpus = [ "cpu-1" "cpu-2" "cpu-3" ];
    reserved-memory = [ "[reserved-memory-1]" "[reserved-memory-2]" ];
    resolv-conf = ./kubelet.nix;
    root-dir = ./.;
    rotate-certificates = true;
    rotate-server-certificates = true;
    runonce = true;
    runtime-cgroups = "[runtime-cgroups]";
    runtime-request-timeout = "[runtime-request-timeout]";
    seccomp-default = true;
    serialize-image-pulls = true;
    storage-driver-buffer-duration = "[storage-driver-buffer-duration]";
    storage-driver-db = "[storage-driver-db]";
    storage-driver-host = "[storage-driver-host]";
    storage-driver-password = "[storage-driver-password]";
    storage-driver-secure = true;
    storage-driver-table = "[storage-driver-table]";
    storage-driver-user = "[storage-driver-user]";
    streaming-connection-idle-timeout = "[streaming-connection-idle-timeout]";
    sync-frequency = "[sync-frequency]";
    system-cgroups = "[system-cgroups]";
    system-reserved = [ "[system-reserved-1]" "[system-reserved-2]" ];
    system-reserved-cgroup = "[system-reserved-cgroup]";
    tls-cert-file = ./kubelet.nix;
    tls-cipher-suites = [ "[tls-cipher-suites-1]" "[tls-cipher-suites-2]" "[tls-cipher-suites-3]" "[tls-cipher-suites-4]" ];
    tls-min-version = "VersionTLS11";
    tls-private-key-file = ./kubelet.nix;
    topology-manager-policy = "none";
    topology-manager-policy-options = [ "[topology-manager-policy-options-1]" "[topology-manager-policy-options-2]" ];
    topology-manager-scope = "pod";
    v = 23;
    vmodule = [ "pattern=1" "pattern=2" ];
    volume-plugin-dir = ./.;
    volume-stats-agg-period = "[volume-stats-agg-period]";
  };
}
