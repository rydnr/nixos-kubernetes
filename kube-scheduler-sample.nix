{ config, pkgs, ... }:

{
  services.kube-scheduler = {
    enable = true;
    configFile = ./kube-scheduler.nix;
    master = "[master]";
    write-config-to = "[write-config-to]"; # ?
    bind-address = "[bind-address]";
    cert-dir = ./.;
    http2-max-streams-per-connection = 1;
    permit-address-sharing = true; # !!
    permit-port-sharing = true; # !!
    secure-port = 2;
    tls-cert-file = ./kube-scheduler.nix;
    tls-cipher-suites = [ "cipher1" "cipher2" ];
    tls-min-version = "VersionTLS13";
    tls-private-key-file = ./kube-scheduler.nix;
    tls-sni-cert-key = [ "example.crt,example.key" "foo.crt,foo.key:*.foo.com,foo.com" ]; # !!
    authentication-kubeconfig = ./kube-scheduler.nix;
    authentication-skip-lookup = true; # !!
    authentication-token-webhook-cache-ttl = "[authentication-token-webhook-cache-ttl]";
    authentication-tolerate-lookup-failure = true; # !!
    client-ca-file = ./kube-scheduler.nix;
    requestheader-allowed-names = [ "name1" "name2" ];
    requestheader-client-ca-file = ./kube-scheduler.nix;
    requestheader-extra-headers-prefix = [ "extraHeadersPrefix1" "extraHeadersPrefix2" "extraHeadersPrefix3" ];
    requestheader-group-headers = [ "groupHeader1" "groupHeader2" ];
    requestheader-username-headers = [ "usernameHeader1" "usernameHeader2" "usernameHeader3" "usernameHeader4" ];
    authorization-always-allow-paths = [ "/healthz" "/readyz" "/livez" ];
    authorization-kubeconfig = ./kube-scheduler.nix;
    authorization-webhook-cache-authorized-ttl = "[authorization-webhook-cache-authorized-ttl]";
    authorization-webhook-cache-unauthorized-ttl = "[authorization-webhook-cache-unauthorized-ttl]";
    contention-profiling = true; # !!
    kube-api-burst = 3;
    kube-api-content-type = "[kube-api-content-type]";
    kube-api-qps = 1.5;
    kubeconfig = ./kube-scheduler.nix;
    pod-max-in-unschedulable-pods-duration = "[pod-max-in-unschedulable-pods-duration]";
    profiling = true; # !!
    leader-elect = true; ## !!
    leader-elect-lease-duration = "[leader-elect-lease-duration]";
    leader-elect-renew-deadline = "[leader-elect-renew-deadline]";
    leader-elect-resource-lock = "endpointsleases";
    leader-elect-resource-name = "[leader-elect-resource-name]";
    leader-elect-resource-namespace = "[leader-elect-resource-namespace]";
    leader-elect-retry-period = "[leader-elect-retry-period]";
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
    allow-metric-labels = [ "metric1,label1='v1,v2,v3'" "metric1,label2='v1,v2,v3'" "metric2,label1='v1,v2,v3'" ]; # ?
    disabled-metrics = [ "metric1" "metric2" ];
    show-hidden-metrics-for-version = "[show-hidden-metrics-for-version]";
    log-flush-frequency = "[log-flush-frequency]";
    log-json-info-buffer-size = "[log-json-info-buffer-size]";
    log-json-split-stream = true;
    logging-format = "json";
    v = 4;
    vmodule = [ "pattern1=1" ];
  };
}
