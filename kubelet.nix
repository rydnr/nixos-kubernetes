{
  config,
  pkgs,
  lib,
  ...
}:

with lib;

let
  cfg = config.services.raw-kubelet;
  boolToString = b: if b then "true" else "false";
  description = "The kubelet is the primary 'node agent' that runs on each node. It can register the node with the apiserver using one of: the hostname; a flag to override the hostname; or specific logic for a cloud provider.";
  longDescription = "The kubelet is the primary 'node agent' that runs on each
node. It can register the node with the apiserver using one of: the hostname; a flag to
override the hostname; or specific logic for a cloud provider.

The kubelet works in terms of a PodSpec. A PodSpec is a YAML or JSON object
that describes a pod. The kubelet takes a set of PodSpecs that are provided through
various mechanisms (primarily through the apiserver) and ensures that the containers
described in those PodSpecs are running and healthy. The kubelet doesn't manage
containers which were not created by Kubernetes.

Other than from an PodSpec from the apiserver, there are two ways that a container
manifest can be provided to the Kubelet.

File: Path passed as a flag on the command line. Files under this path will be monitored
periodically for updates. The monitoring period is 20s by default and is configurable
via a flag.

HTTP endpoint: HTTP endpoint passed as a parameter on the command line. This endpoint
is checked every 20 seconds (also configurable with a flag).";
  featureGatesDescription = ''
A set of key=value pairs that describe feature gates for alpha/experimental features. Options are:
  APIResponseCompression=true|false (BETA - default=true)
  APIServerIdentity=true|false (BETA - default=true)
  APIServerTracing=true|false (BETA - default=true)
  APIServingWithRoutine=true|false (BETA - default=true)
  AllAlpha=true|false (ALPHA - default=false)
  AllBeta=true|false (BETA - default=false)
  AnyVolumeDataSource=true|false (BETA - default=true)
  AppArmor=true|false (BETA - default=true)
  AppArmorFields=true|false (BETA - default=true)
  CPUManagerPolicyAlphaOptions=true|false (ALPHA - default=false)
  CPUManagerPolicyBetaOptions=true|false (BETA - default=true)
  CPUManagerPolicyOptions=true|false (BETA - default=true)
  CRDValidationRatcheting=true|false (BETA - default=true)
  CSIMigrationPortworx=true|false (BETA - default=false)
  CSIVolumeHealth=true|false (ALPHA - default=false)
  CloudControllerManagerWebhook=true|false (ALPHA - default=false)
  ClusterTrustBundle=true|false (ALPHA - default=false)
  ClusterTrustBundleProjection=true|false (ALPHA - default=false)
  ComponentSLIs=true|false (BETA - default=true)
  ConsistentListFromCache=true|false (ALPHA - default=false)
  ContainerCheckpoint=true|false (BETA - default=true)
  ContextualLogging=true|false (BETA - default=true)
  CronJobsScheduledAnnotation=true|false (BETA - default=true)
  CrossNamespaceVolumeDataSource=true|false (ALPHA - default=false)
  CustomCPUCFSQuotaPeriod=true|false (ALPHA - default=false)
  CustomResourceFieldSelectors=true|false (ALPHA - default=false)
  DevicePluginCDIDevices=true|false (BETA - default=true)
  DisableCloudProviders=true|false (BETA - default=true)
  DisableKubeletCloudCredentialProviders=true|false (BETA - default=true)
  DisableNodeKubeProxyVersion=true|false (ALPHA - default=false)
  DynamicResourceAllocation=true|false (ALPHA - default=false)
  ElasticIndexedJob=true|false (BETA - default=true)
  EventedPLEG=true|false (ALPHA - default=false)
  GracefulNodeShutdown=true|false (BETA - default=true)
  GracefulNodeShutdownBasedOnPodPriority=true|false (BETA - default=true)
  HPAScaleToZero=true|false (ALPHA - default=false)
  HonorPVReclaimPolicy=true|false (ALPHA - default=false)
  ImageMaximumGCAge=true|false (BETA - default=true)
  InPlacePodVerticalScaling=true|false (ALPHA - default=false)
  InTreePluginAWSUnregister=true|false (ALPHA - default=false)
  InTreePluginAzureDiskUnregister=true|false (ALPHA - default=false)
  InTreePluginAzureFileUnregister=true|false (ALPHA - default=false)
  InTreePluginGCEUnregister=true|false (ALPHA - default=false)
  InTreePluginOpenStackUnregister=true|false (ALPHA - default=false)
  InTreePluginPortworxUnregister=true|false (ALPHA - default=false)
  InTreePluginvSphereUnregister=true|false (ALPHA - default=false)
  InformerResourceVersion=true|false (ALPHA - default=false)
  JobBackoffLimitPerIndex=true|false (BETA - default=true)
  JobManagedBy=true|false (ALPHA - default=false)
  JobPodFailurePolicy=true|false (BETA - default=true)
  JobPodReplacementPolicy=true|false (BETA - default=true)
  JobSuccessPolicy=true|false (ALPHA - default=false)
  KubeProxyDrainingTerminatingNodes=true|false (BETA - default=true)
  KubeletCgroupDriverFromCRI=true|false (ALPHA - default=false)
  KubeletInUserNamespace=true|false (ALPHA - default=false)
  KubeletPodResourcesDynamicResources=true|false (ALPHA - default=false)
  KubeletPodResourcesGet=true|false (ALPHA - default=false)
  KubeletSeparateDiskGC=true|false (ALPHA - default=false)
  KubeletTracing=true|false (BETA - default=true)
  LoadBalancerIPMode=true|false (BETA - default=true)
  LocalStorageCapacityIsolationFSQuotaMonitoring=true|false (ALPHA - default=false)
  LogarithmicScaleDown=true|false (BETA - default=true)
  LoggingAlphaOptions=true|false (ALPHA - default=false)
  LoggingBetaOptions=true|false (BETA - default=true)
  MatchLabelKeysInPodAffinity=true|false (ALPHA - default=false)
  MatchLabelKeysInPodTopologySpread=true|false (BETA - default=true)
  MaxUnavailableStatefulSet=true|false (ALPHA - default=false)
  MemoryManager=true|false (BETA - default=true)
  MemoryQoS=true|false (ALPHA - default=false)
  MultiCIDRServiceAllocator=true|false (ALPHA - default=false)
  MutatingAdmissionPolicy=true|false (ALPHA - default=false)
  NFTablesProxyMode=true|false (ALPHA - default=false)
  NodeInclusionPolicyInPodTopologySpread=true|false (BETA - default=true)
  NodeLogQuery=true|false (BETA - default=false)
  NodeSwap=true|false (BETA - default=true)
  OpenAPIEnums=true|false (BETA - default=true)
  PDBUnhealthyPodEvictionPolicy=true|false (BETA - default=true)
  PersistentVolumeLastPhaseTransitionTime=true|false (BETA - default=true)
  PodAndContainerStatsFromCRI=true|false (ALPHA - default=false)
  PodDeletionCost=true|false (BETA - default=true)
  PodDisruptionConditions=true|false (BETA - default=true)
  PodIndexLabel=true|false (BETA - default=true)
  PodLifecycleSleepAction=true|false (BETA - default=true)
  PodReadyToStartContainersCondition=true|false (BETA - default=true)
  PortForwardWebsockets=true|false (ALPHA - default=false)
  ProcMountType=true|false (ALPHA - default=false)
  QOSReserved=true|false (ALPHA - default=false)
  RecoverVolumeExpansionFailure=true|false (ALPHA - default=false)
  RecursiveReadOnlyMounts=true|false (ALPHA - default=false)
  RelaxedEnvironmentVariableValidation=true|false (ALPHA - default=false)
  RetryGenerateName=true|false (ALPHA - default=false)
  RotateKubeletServerCertificate=true|false (BETA - default=true)
  RuntimeClassInImageCriApi=true|false (ALPHA - default=false)
  SELinuxMount=true|false (ALPHA - default=false)
  SELinuxMountReadWriteOncePod=true|false (BETA - default=true)
  SchedulerQueueingHints=true|false (BETA - default=false)
  SeparateCacheWatchRPC=true|false (BETA - default=true)
  SeparateTaintEvictionController=true|false (BETA - default=true)
  ServiceAccountTokenJTI=true|false (BETA - default=true)
  ServiceAccountTokenNodeBinding=true|false (ALPHA - default=false)
  ServiceAccountTokenNodeBindingValidation=true|false (BETA - default=true)
  ServiceAccountTokenPodNodeInfo=true|false (BETA - default=true)
  ServiceTrafficDistribution=true|false (ALPHA - default=false)
  SidecarContainers=true|false (BETA - default=true)
  SizeMemoryBackedVolumes=true|false (BETA - default=true)
  StatefulSetAutoDeletePVC=true|false (BETA - default=true)
  StatefulSetStartOrdinal=true|false (BETA - default=true)
  StorageNamespaceIndex=true|false (BETA - default=true)
  StorageVersionAPI=true|false (ALPHA - default=false)
  StorageVersionHash=true|false (BETA - default=true)
  StorageVersionMigrator=true|false (ALPHA - default=false)
  StructuredAuthenticationConfiguration=true|false (BETA - default=true)
  StructuredAuthorizationConfiguration=true|false (BETA - default=true)
  TopologyAwareHints=true|false (BETA - default=true)
  TopologyManagerPolicyAlphaOptions=true|false (ALPHA - default=false)
  TopologyManagerPolicyBetaOptions=true|false (BETA - default=true)
  TopologyManagerPolicyOptions=true|false (BETA - default=true)
  TranslateStreamCloseWebsocketRequests=true|false (BETA - default=true)
  UnauthenticatedHTTP2DOSMitigation=true|false (BETA - default=true)
  UnknownVersionInteroperabilityProxy=true|false (ALPHA - default=false)
  UserNamespacesPodSecurityStandards=true|false (ALPHA - default=false)
  UserNamespacesSupport=true|false (BETA - default=false)
  VolumeAttributesClass=true|false (ALPHA - default=false)
  VolumeCapacityPriority=true|false (ALPHA - default=false)
  WatchFromStorageWithoutResourceVersion=true|false (BETA - default=false)
  WatchList=true|false (ALPHA - default=false)
  WatchListClient=true|false (BETA - default=false)
  WinDSR=true|false (ALPHA - default=false)
  WinOverlay=true|false (BETA - default=true)
  WindowsHostNetwork=true|false (ALPHA - default=true)
'';

in
{
  options.services.raw-kubelet = {
    enable = mkOption {
      type = types.bool;
      default = false;
      inherit description;
    };

    address = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address for the Kubelet to serve on (set to '0.0.0.0' or '::' for listening on all interfaces and IP address families) (default 0.0.0.0) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    allowed-unsafe-sysctls = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Whitelist of unsafe sysctls or unsafe sysctl patterns (ending in *). Use these at your own risk. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    anonymous-auth = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enables anonymous requests to the Kubelet server. Requests that are not rejected by another authentication method are treated as anonymous requests. Anonymous requests have a username of system:anonymous, and a group name of system:unauthenticated. (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    application-metrics-count-limit = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Max number of application metrics to store (per container) (default 100) (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    authentication-token-webhook = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Use the TokenReview API to determine authentication for bearer tokens. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    authentication-token-webhook-cache-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache responses from the webhook token authenticator. (default 2m0s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    authorization-mode = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Authorization mode for Kubelet server. Valid options are AlwaysAllow or Webhook. Webhook mode uses the SubjectAccessReview API to determine authorization. (default 'AlwaysAllow') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    authorization-webhook-cache-authorized-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache 'authorized' responses from the webhook authorizer. (default 5m0s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    authorization-webhook-cache-unauthorized-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache 'unauthorized' responses from the webhook authorizer. (default 30s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    boot-id-file = mkOption {
      type = types.nullOr (types.listOf types.path);
      default = null;
      description = "Comma-separated list of files to check for boot-id. Use the first one that exists. (default '/proc/sys/kernel/random/boot_id') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    bootstrap-kubeconfig = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a kubeconfig file that will be used to get client certificate for kubelet. If the file specified by --kubeconfig does not exist, the bootstrap kubeconfig is used to request a client certificate from the API server. On success, a kubeconfig file referencing the generated client certificate and key is written to the path specified by --kubeconfig. The client certificate and key file will be stored in the directory pointed by --cert-dir.";
    };

    cert-dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The directory where the TLS certs are located. If --tls-cert-file and --tls-private-key-file are provided, this flag will be ignored. (default '/var/lib/kubelet/pki')";
    };

    cgroup-driver = mkOption {
      type = types.nullOr (types.enum [ "cgroupfs" "systemd" ]);
      default = null;
      description = "Driver that the kubelet uses to manipulate cgroups on the host.  Possible values: 'cgroupfs', 'systemd' (default 'cgroupfs') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cgroup-root = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Optional root cgroup to use for pods. This is handled by the container runtime on a best effort basis. Default: '', which means use the container runtime default. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cgroups-per-qos = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable creation of QoS cgroup hierarchy, if true top level QoS and pod cgroups are created. (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    client-ca-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cloud-config = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The path to the cloud provider configuration file. Empty string for no configuration file. (DEPRECATED: will be removed in 1.25 or later, in favor of removing cloud provider code from Kubelet.)";
    };

    cloud-provider = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The provider for cloud services. Set to empty string for running with no cloud provider. If set, the cloud provider determines the name of the node (consult cloud provider documentation to determine if and how the hostname is used). (DEPRECATED: will be removed in 1.25 or later, in favor of removing cloud provider code from Kubelet.)";
    };

    cluster-dns = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Comma-separated list of DNS server IP address.  This value is used for containers DNS server in case of Pods with 'dnsPolicy=ClusterFirst'. Note: all DNS servers appearing in the list MUST serve the same set of records otherwise name resolution within the cluster may not work correctly. There is no guarantee as to which DNS server may be contacted for name resolution. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cluster-domain = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Domain for this cluster.  If set, kubelet will configure all containers to search this domain in addition to the host's search domains (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The Kubelet will load its initial configuration from this file. The path may be absolute or relative; relative paths start at the Kubelet's current working directory. Omit this flag to use the built-in default configuration values. Command-line flags override configuration from this file.";
    };

    config-dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a directory to specify drop-ins, allows the user to optionally specify additional configs to overwrite what is provided by default and in the KubeletConfigFile flag. Note: Set the 'KUBELET_CONFIG_DROPIN_DIR_ALPHA' environment variable to specify the directory. [default='']";
    };

    container-hints = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Location of the container hints file (default '/etc/cadvisor/container_hints.json') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    container-log-max-files = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "<Warning: Beta feature> Set the maximum number of container log files that can be present for a container. The number must be >= 2. (default 5) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    container-log-max-size = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "<Warning: Beta feature> Set the maximum size (e.g. 10Mi) of container log file before it is rotated. (default "10Mi") (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    container-runtime-endpoint = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The endpoint of container runtime service. Unix Domain Sockets are supported on Linux, while npipe and tcp endpoints are supported on Windows. Examples:'unix:///path/to/runtime.sock', 'npipe:////./pipe/runtime' (default 'unix:///run/containerd/containerd.sock') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    containerd = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Containerd endpoint (default '/run/containerd/containerd.sock') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    containerd-namespace = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "containerd namespace (default 'k8s.io') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    contention-profiling = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable block profiling, if profiling is enabled (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cpu-cfs-quota = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable CPU CFS quota enforcement for containers that specify CPU limits (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cpu-cfs-quota-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Sets CPU CFS quota period value, cpu.cfs_period_us, defaults to Linux Kernel default (default 100ms) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cpu-manager-policy = mkOption {
      type = types.nullOr (types.enum [ "none" "static" ]);
      default = null;
      description = "CPU Manager policy to use. Possible values: 'none', 'static'. (default "none") (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cpu-manager-policy-options = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A set of key=value CPU Manager policy options to use, to fine tune their behaviour. If not supplied, keep the default behaviour. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    cpu-manager-reconcile-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "<Warning: Alpha feature> CPU Manager reconciliation period. Examples: '10s', or '1m'. If not supplied, defaults to 'NodeStatusUpdateFrequency' (default 10s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    enable-controller-attach-detach = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enables the Attach/Detach controller to manage attachment/detachment of volumes scheduled to this node, and disables kubelet from executing any attach/detach operations (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    enable-debugging-handlers = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enables server endpoints for log collection and local running of containers and commands (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    enable-load-reader = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Whether to enable cpu load reader (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    enable-server = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Enable the Kubelet's server (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    enforce-node-allocatable = mkOption {
      type = types.nullOr (types.listOf (types.enum [ "none" "pods" "system-reserved" "kube-reserved" ]));
      default = null;
      description = "A list of levels of node allocatable enforcement to be enforced by kubelet. Acceptable options are 'none', 'pods', 'system-reserved', and 'kube-reserved'. If the latter two options are specified, '--system-reserved-cgroup' and '--kube-reserved-cgroup' must also be set, respectively. If 'none' is specified, no additional options should be set. See https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/ for more details. (default [pods]) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    event-burst = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum size of a bursty event records, temporarily allows event records to burst to this number, while still not exceeding event-qps. The number must be >= 0. If 0 will use DefaultBurst: 10. (default 100) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    event-qps = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "QPS to limit event creations. The number must be >= 0. If 0 will use DefaultQPS: 5. (default 50) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    event-storage-age-limit = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Max length of time for which to store events (per type). Value is a comma separated list of key values, where the keys are event types (e.g.: creation, oom) or 'default' and the value is a duration. Default is applied to all non-specified event types (default 'default=0') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    event-storage-event-limit = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Max number of events to store (per type). Value is a comma separated list of key values, where the keys are event types (e.g.: creation, oom) or 'default' and the value is an integer. Default is applied to all non-specified event types (default 'default=0') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    eviction-hard = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A set of eviction thresholds (e.g. memory.available<1Gi) that if met would trigger a pod eviction. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    eviction-max-pod-grace-period = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum allowed grace period (in seconds) to use when terminating pods in response to a soft eviction threshold being met.  If negative, defer to pod specified value. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    eviction-minimum-reclaim = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A set of minimum reclaims (e.g. imagefs.available=2Gi) that describes the minimum amount of resource the kubelet will reclaim when performing a pod eviction if that resource is under pressure. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    eviction-pressure-transition-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Duration for which the kubelet has to wait before transitioning out of an eviction pressure condition. (default 5m0s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    eviction-soft = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A set of eviction thresholds (e.g. memory.available<1.5Gi) that if met over a corresponding grace period would trigger a pod eviction. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    eviction-soft-grace-period = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A set of eviction grace periods (e.g. memory.available=1m30s) that correspond to how long a soft eviction threshold must hold before triggering a pod eviction. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    exit-on-lock-contention = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Whether kubelet should exit upon lock-file contention.";
    };

    experimental-allocatable-ignore-eviction = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "When set to 'true', Hard Eviction Thresholds will be ignored while calculating Node Allocatable. See https://kubernetes.io/docs/tasks/administer-cluster/reserve-compute-resources/ for more details. [default=false] (DEPRECATED: will be removed in 1.25 or later.)";
    };

    experimental-mounter-path = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "[Experimental] Path of mounter binary. Leave empty to use the default mount. (DEPRECATED: will be removed in 1.25 or later. in favor of using CSI.)";
    };

    fail-swap-on = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Makes the Kubelet fail to start if swap is enabled on the node.  (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    feature-gates = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = featureGatesDescription;
    };

    file-check-frequency = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Duration between checking config files for new data (default 20s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    global-housekeeping-interval = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Interval between global housekeepings (default 1m0s) (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    hairpin-mode = mkOption {
      type = types.nullOr (types.enum [ "promiscuous-bridge" "hairpin-veth" "none" ]);
      default = null;
      description = "How should the kubelet setup hairpin NAT. This allows endpoints of a Service to loadbalance back to themselves if they should try to access their own Service. Valid values are 'promiscuous-bridge', 'hairpin-veth' and 'none'. (default 'promiscuous-bridge') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    healthz-bind-address = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address for the healthz server to serve on (set to '0.0.0.0' or '::' for listening on all interfaces and IP address families) (default 127.0.0.1) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    healthz-port = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The port of the localhost healthz endpoint (set to 0 to disable) (default 10248) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    hostname-override = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "If non-empty, will use this string as identification instead of the actual hostname. If --cloud-provider is set, the cloud provider determines the name of the node (consult cloud provider documentation to determine if and how the hostname is used).";
    };

    housekeeping-interval = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Interval between container housekeepings (default 10s)";
    };

    http-check-frequency = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Duration between checking http for new data (default 20s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    image-credential-provider-bin-dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The path to the directory where credential provider plugin binaries are located.";
    };

    image-credential-provider-config = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The path to the credential provider plugin config file.";
    };

    image-gc-high-threshold = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The percent of disk usage after which image garbage collection is always run. Values must be within the range [0, 100], To disable image garbage collection, set to 100.  (default 85) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    image-gc-low-threshold = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The percent of disk usage before which image garbage collection is never run. Lowest disk usage to garbage collect to. Values must be within the range [0, 100] and must be less than that of --image-gc-high-threshold. (default 80) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    image-service-endpoint = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The endpoint of container image service. If not specified, it will be the same with --container-runtime-endpoint by default. Unix Domain Socket are supported on Linux, while npipe and tcp endpoints are supported on Windows. Examples:'unix:///path/to/runtime.sock', 'npipe:////./pipe/runtime' (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    keep-terminated-pod-volumes = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Keep terminated pod volumes mounted to the node after the pod terminates.  Can be useful for debugging volume related issues. (DEPRECATED: will be removed in a future version)";
    };

    kernel-memcg-notification = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "If enabled, the kubelet will integrate with the kernel memcg notification to determine if memory eviction thresholds are crossed rather than polling. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    kube-api-burst = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Burst to use while talking with kubernetes apiserver. The number must be >= 0. If 0 will use DefaultBurst: 100. Doesn't cover events and node heartbeat apis which rate limiting is controlled by a different set of flags (default 100) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    kube-api-content-type = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Content type of requests sent to apiserver. (default "application/vnd.kubernetes.protobuf") (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    kube-api-qps = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "QPS to use while talking with kubernetes apiserver. The number must be >= 0. If 0 will use DefaultQPS: 50. Doesn't cover events and node heartbeat apis which rate limiting is controlled by a different set of flags (default 50) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    kube-reserved = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A set of ResourceName=ResourceQuantity (e.g. cpu=200m,memory=500Mi,ephemeral-storage=1Gi) pairs that describe resources reserved for kubernetes system components. Currently only cpu, memory and local ephemeral storage for root file system are supported. See https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ for more detail. [default=none] (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    kube-reserved-cgroup = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Absolute name of the top level cgroup that is used to manage kubernetes components for which compute resources were reserved via '--kube-reserved' flag. Ex. '/kube-reserved'. [default=''] (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    kubeconfig = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a kubeconfig file, specifying how to connect to the API server. Providing --kubeconfig enables API server mode, omitting --kubeconfig enables standalone mode.";
    };

    kubelet-cgroups = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Optional absolute name of cgroups to create and run the Kubelet in. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    local-storage-capacity-isolation = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, local ephemeral storage isolation is enabled. Otherwise, local storage isolation feature will be disabled (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    lock-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "<Warning: Alpha feature> The path to file for kubelet to use as a lock file.";
    };

    log-cadvisor-usage = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Whether to log the usage of the cAdvisor container (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    log-flush-frequency = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Maximum number of seconds between log flushes (default 5s)";
    };

    log-json-info-buffer-size = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "[Alpha] In JSON format with split output streams, the info messages can be buffered for a while to increase performance. The default value of zero bytes disables buffering. The size can be specified as number of bytes (512), multiples of 1000 (1K), multiples of 1024 (2Ki), or powers of those (3M, 4G, 5Mi, 6Gi). Enable the LoggingAlphaOptions feature gate to use this. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    log-json-split-stream = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "[Alpha] In JSON format, write error messages to stderr and info messages to stdout. The default is to write a single stream to stdout. Enable the LoggingAlphaOptions feature gate to use this. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    logging-format = mkOption {
      type = types.nullOr (types.enum [ "json" "text" ]);
      default = null;
      description = "Sets the log format. Permitted formats: 'json' (gated by LoggingBetaOptions), 'text'. (default 'text') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    machine-id-file = mkOption {
      type = types.nullOr (types.listOf types.path);
      default = null;
      description = "List of files to check for machine-id. Use the first one that exists. (default '/etc/machine-id,/var/lib/dbus/machine-id') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    make-iptables-util-chains = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, kubelet will ensure iptables utility rules are present on host. (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    manifest-url = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "URL for accessing additional Pod specifications to run (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    manifest-url-header = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of HTTP headers to use when accessing the url provided to --manifest-url. Multiple headers with the same name will be added in the same order provided. This flag can be repeatedly invoked. For example: --manifest-url-header 'a:hello,b:again,c:world' --manifest-url-header 'b:beautiful' (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    max-open-files = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Number of files that can be opened by Kubelet process. (default 1000000) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    max-pods = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Number of Pods that can run on this Kubelet. (default 110) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    maximum-dead-containers = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum number of old instances of containers to retain globally.  Each container takes up some disk space. To disable, set to a negative number. (default -1) (DEPRECATED: Use --eviction-hard or --eviction-soft instead. Will be removed in a future version.)";
    };

    maximum-dead-containers-per-container = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum number of old instances to retain per container.  Each container takes up some disk space. (default 1) (DEPRECATED: Use --eviction-hard or --eviction-soft instead. Will be removed in a future version.)";
    };

    memory-manager-policy = mkOption {
      type = types.nullOr (types.enum [ "None" "Static" ]);
      default = null;
      description = "Memory Manager policy to use. Possible values: 'None', 'Static'. (default 'None') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    minimum-container-ttl-duration = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Minimum age for a finished container before it is garbage collected.  Examples: '300ms', '10s' or '2h45m' (DEPRECATED: Use --eviction-hard or --eviction-soft instead. Will be removed in a future version.)";
    };

    minimum-image-ttl-duration = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Minimum age for an unused image before it is garbage collected.  Examples: '300ms', '10s' or '2h45m'. (default 2m0s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    node-ip = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "IP address (or comma-separated dual-stack IP addresses) of the node. If unset, kubelet will use the node's default IPv4 address, if any, or its default IPv6 address if it has no IPv4 addresses. You can pass '::' to make it prefer the default IPv6 address rather than the default IPv4 address.";
    };

    node-labels = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "<Warning: Alpha feature> Labels to add when registering the node in the cluster.  Labels must be key=value pairs separated by ','. Labels in the 'kubernetes.io' namespace must begin with an allowed prefix (kubelet.kubernetes.io, node.kubernetes.io) or be in the specifically allowed set (beta.kubernetes.io/arch, beta.kubernetes.io/instance-type, beta.kubernetes.io/os, failure-domain.beta.kubernetes.io/region, failure-domain.beta.kubernetes.io/zone, kubernetes.io/arch, kubernetes.io/hostname, kubernetes.io/os, node.kubernetes.io/instance-type, topology.kubernetes.io/region, topology.kubernetes.io/zone)";
    };

    node-status-max-images = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The maximum number of images to report in Node.Status.Images. If -1 is specified, no cap will be applied. (default 50) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    node-status-update-frequency = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Specifies how often kubelet posts node status to master. Note: be cautious when changing the constant, it must work with nodeMonitorGracePeriod in nodecontroller. (default 10s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    oom-score-adj = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The oom-score-adj value for kubelet process. Values must be within the range [-1000, 1000] (default -999) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    pod-cidr = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The CIDR to use for pod IP addresses, only used in standalone mode.  In cluster mode, this is obtained from the master. For IPv6, the maximum number of IP's allocated is 65536 (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    pod-infra-container-image = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Specified image will not be pruned by the image garbage collector. CRI implementations have their own configuration to set this image. (default 'registry.k8s.io/pause:3.9') (DEPRECATED: will be removed in a future release. Image garbage collector will get sandbox image information from CRI.)";
    };

    pod-manifest-path = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the directory containing static pod files to run, or the path to a single static pod file. Files starting with dots will be ignored. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    pod-max-pids = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Set the maximum number of processes per pod.  If -1, the kubelet defaults to the node allocatable pid capacity. (default -1) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    pods-per-core = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Number of Pods per core that can run on this Kubelet. The total number of Pods on this Kubelet cannot exceed max-pods, so max-pods will be used if this calculation results in a larger number of Pods allowed on the Kubelet. A value of 0 disables this limit. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    port = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The port for the Kubelet to serve on. (default 10250) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    protect-kernel-defaults = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Default kubelet behaviour for kernel tuning. If set, kubelet errors if any of kernel tunables is different than kubelet defaults. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    provider-id = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Unique identifier for identifying the node in a machine database, i.e cloudprovider";
    };

    qos-reserved = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "<Warning: Alpha feature> A set of ResourceName=Percentage (e.g. memory=50%) pairs that describe how pod resource requests are reserved at the QoS level. Currently only memory is supported. Requires the QOSReserved feature gate to be enabled. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    read-only-port = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The read-only port for the Kubelet to serve on with no authentication/authorization (set to 0 to disable) (default 10255) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    register-node = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Register the node with the apiserver. If --kubeconfig is not provided, this flag is irrelevant, as the Kubelet won't have an apiserver to register with. (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    register-schedulable = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Register the node as schedulable. Won't have any effect if register-node is false. (default true) (DEPRECATED: will be removed in a future version)";
    };

    register-with-taints = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Register the node with the given list of taints (comma separated '<key>=<value>:<effect>'). No-op if register-node is false. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    registry-burst = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum size of a bursty pulls, temporarily allows pulls to burst to this number, while still not exceeding registry-qps. Only used if --registry-qps > 0 (default 10) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    registry-qps = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "If > 0, limit registry pull QPS to this value.  If 0, unlimited. (default 5) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    reserved-cpus = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of CPUs or CPU ranges that are reserved for system and kubernetes usage. This specific list will supersede cpu counts in --system-reserved and --kube-reserved. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    reserved-memory = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of memory reservations for NUMA nodes. (e.g. --reserved-memory 0:memory=1Gi,hugepages-1M=2Gi --reserved-memory 1:memory=2Gi). The total sum for each memory type should be equal to the sum of kube-reserved, system-reserved and eviction-threshold. See https://kubernetes.io/docs/tasks/administer-cluster/memory-manager/#reserved-memory-flag for more details. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    resolv-conf = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Resolver configuration file used as the basis for the container DNS resolution configuration. (default "/etc/resolv.conf") (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    root-dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Directory path for managing kubelet files (volume mounts,etc). (default '/var/lib/kubelet')";
    };

    rotate-certificates = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Auto rotate the kubelet client certificates by requesting new certificates from the kube-apiserver when the certificate expiration approaches. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    rotate-server-certificates = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Auto-request and rotate the kubelet serving certificates by requesting new certificates from the kube-apiserver when the certificate expiration approaches. Requires the RotateKubeletServerCertificate feature gate to be enabled, and approval of the submitted CertificateSigningRequest objects. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    runonce = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, exit after spawning pods from static pod files or remote urls. Exclusive with --enable-server (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    runtime-cgroups = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Optional absolute name of cgroups to create and run the runtime in.";
    };

    runtime-request-timeout = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Timeout of all runtime requests except long running request - pull, logs, exec and attach. When timeout exceeded, kubelet will cancel the request, throw out an error and retry later. (default 2m0s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    seccomp-default = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable the use of RuntimeDefault as the default seccomp profile for all workloads.";
    };

    serialize-image-pulls = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Pull images one at a time. We recommend *not* changing the default value on nodes that run docker daemon with version < 1.9 or an Aufs storage backend. Issue #10959 has more details. (default true) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    storage-driver-buffer-duration = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Writes in the storage driver will be buffered for this duration, and committed to the non memory backends as a single transaction (default 1m0s) (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    storage-driver-db = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Database name (default 'cadvisor') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    storage-driver-host = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Database host:port (default 'localhost:8086') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    storage-driver-password = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Database password (default 'root') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    storage-driver-secure = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Use secure connection with database (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    storage-driver-table = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Table name (default 'stats') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    storage-driver-user = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Database username (default 'root') (DEPRECATED: This is a cadvisor flag that was mistakenly registered with the Kubelet. Due to legacy concerns, it will follow the standard CLI deprecation timeline before being removed.)";
    };

    streaming-connection-idle-timeout = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Maximum time a streaming connection can be idle before the connection is automatically closed. 0 indicates no timeout. Example: '5m'. Note: All connections to the kubelet server have a maximum duration of 4 hours. (default 4h0m0s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    sync-frequency = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Max period between synchronizing running containers and config (default 1m0s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    system-cgroups = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Optional absolute name of cgroups in which to place all non-kernel processes that are not already inside a cgroup under '/'. Empty for no container. Rolling back the flag requires a reboot. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    system-reserved = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A set of ResourceName=ResourceQuantity (e.g. cpu=200m,memory=500Mi,ephemeral-storage=1Gi) pairs that describe resources reserved for non-kubernetes components. Currently only cpu, memory and local ephemeral storage for root file system are supported. See https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/ for more detail. [default=none] (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    system-reserved-cgroup = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Absolute name of the top level cgroup that is used to manage non-kubernetes components for which compute resources were reserved via '--system-reserved' flag. Ex. '/system-reserved'. [default=''] (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    tls-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File containing x509 Certificate used for serving HTTPS (with intermediate certs, if any, concatenated after server cert). If --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to the directory passed to --cert-dir. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    tls-cipher-suites = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of cipher suites for the server. If omitted, the default Go cipher suites will be used. ";
    };

    tls-min-version = mkOption {
      type = types.nullOr (types.enum [ "VersionTLS10" "VersionTLS11" "VersionTLS12" "VersionsTLS13" ]);
      default = null;
      description = "Minimum TLS version supported. Possible values: VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13 (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    tls-private-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File containing x509 private key matching --tls-cert-file. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    topology-manager-policy = mkOption {
      type = types.nullOr (types.enum [ "none" "best-effort" "restricted" "single-numa-mode" ]);
      default = null;
      description = "Topology Manager policy to use. Possible values: 'none', 'best-effort', 'restricted', 'single-numa-node'. (default 'none') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    topology-manager-policy-options = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A set of key=value Topology Manager policy options to use, to fine tune their behaviour. If not supplied, keep the default behaviour. (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    topology-manager-scope = mkOption {
      type = types.nullOr (types.enum [ "container" "pod" ]);
      default = null;
      description = "Scope to which topology hints applied. Topology Manager collects hints from Hint Providers and applies them to defined scope to ensure the pod admission. Possible values: 'container', 'pod'. (default 'container') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    v = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Number for the log level verbosity";
    };

    vmodule = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of pattern=N settings for file-filtered logging (only works for text log format)";
    };

    volume-plugin-dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The full path of the directory in which to search for additional third party volume plugins (default '/usr/libexec/kubernetes/kubelet-plugins/volume/exec/') (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };

    volume-stats-agg-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Specifies interval for kubelet to calculate and cache the volume disk usage for all pods and volumes.  To disable volume calculations, set to a negative number. (default 1m0s) (DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag. See https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/ for more information.)";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.kubelet = lib.mkForce {
      inherit description;
      wantedBy = [ "kubernetes.target" ];
      after = [ "containerd.service" "network.target" ] ; # "kube-apiserver.service" ];
      path = with pkgs; [
        gitMinimal
        openssh
        util-linux
        iproute
        ethtool
        thin-provisioning-tools
        iptables
        socat
      ] ++ lib.optional config.boot.zfs.enabled config.boot.zfs.package;

      serviceConfig = {
        Slice = "kubernetes.slice";
        CPUAccounting = true;
        MemoryAccounting = true;
        Restart = "on-failure";
        RestartSec = "1000ms";
        ExecStart = ''
          ${pkgs.kubernetes}/bin/kubelet \
            ${optionalString (cfg.address != null) "--address ${toString cfg.address}"} \
            ${optionalString (cfg.allowed-unsafe-sysctls != null) "--allowed-unsafe-sysctls \"${concatStringsSep "," cfg.allowed-unsafe-sysctls}\""} \
            ${optionalString (cfg.anonymous-auth != null) "--anonymous-auth"} \
            ${optionalString (cfg.application-metrics-count-limit != null) "--application-metrics-count-limit ${toString cfg.application-metrics-count-limit}"} \
            ${optionalString (cfg.authentication-token-webhook != null) "--authentication-token-webhook"} \
            ${optionalString (cfg.authentication-token-webhook-cache-ttl != null) "--authentication-token-webhook-cache-ttl ${toString cfg.authentication-token-webhook-cache-ttl}"} \
            ${optionalString (cfg.authorization-mode != null) "--authorization-mode ${toString cfg.authorization-mode}"} \
            ${optionalString (cfg.authorization-webhook-cache-authorized-ttl != null) "--authorization-webhook-cache-authorized-ttl ${toString cfg.authorization-webhook-cache-authorized-ttl}"} \
            ${optionalString (cfg.authorization-webhook-cache-unauthorized-ttl != null) "--authorization-webhook-cache-unauthorized-ttl ${toString cfg.authorization-webhook-cache-unauthorized-ttl}"} \
            ${optionalString (cfg.boot-id-file != null) "--boot-id-file \"${concatStringsSep "," cfg.boot-id-file}\""} \
            ${optionalString (cfg.bootstrap-kubeconfig != null) "--bootstrap-kubeconfig ${toString cfg.bootstrap-kubeconfig}"} \
            ${optionalString (cfg.cert-dir != null) "--cert-dir ${toString cfg.cert-dir}"} \
            ${optionalString (cfg.cgroup-driver != null) "--cgroup-driver ${toString cfg.cgroup-driver}"} \
            ${optionalString (cfg.cgroup-root != null) "--cgroup-root ${toString cfg.cgroup-root}"} \
            ${optionalString (cfg.cgroups-per-qos != null) "--cgroups-per-qos ${boolToString cfg.cgroups-per-qos}"} \
            ${optionalString (cfg.client-ca-file != null) "--client-ca-file ${toString cfg.client-ca-file}"} \
            ${optionalString (cfg.cloud-config != null) "--cloud-config ${toString cfg.cloud-config}"} \
            ${optionalString (cfg.cloud-provider != null) "--cloud-provider ${toString cfg.cloud-provider}"} \
            ${optionalString (cfg.cluster-dns != null) "--cluster-dns \"${concatStringsSep "," cfg.cluster-dns}\""} \
            ${optionalString (cfg.cluster-domain != null) "--cluster-domain ${toString cfg.cluster-domain}"} \
            ${optionalString (cfg.configFile != null) "--config ${toString cfg.configFile}"} \
            ${optionalString (cfg.config-dir != null) "--config-dir ${toString cfg.config-dir}"} \
            ${optionalString (cfg.container-hints != null) "--container-hints ${toString cfg.container-hints}"} \
            ${optionalString (cfg.container-log-max-files != null) "--container-log-max-files ${toString cfg.container-log-max-files}"} \
            ${optionalString (cfg.container-log-max-size != null) "--container-log-max-size ${toString cfg.container-log-max-size}"} \
            ${optionalString (cfg.container-runtime-endpoint != null) "--container-runtime-endpoint ${toString cfg.container-runtime-endpoint}"} \
            ${optionalString (cfg.containerd != null) "--containerd ${toString cfg.containerd}"} \
            ${optionalString (cfg.containerd-namespace != null) "--containerd-namespace ${toString cfg.containerd-namespace}"} \
            ${optionalString (cfg.contention-profiling != null) "--contention-profiling"} \
            ${optionalString (cfg.cpu-cfs-quota != null) "--cpu-cfs-quota ${toString cfg.cpu-cfs-quota}"} \
            ${optionalString (cfg.cpu-cfs-quota-period != null) "--cpu-cfs-quota-period ${toString cfg.cpu-cfs-quota-period}"} \
            ${optionalString (cfg.cpu-manager-policy-options != null) "--cpu-manager-policy-options \"${concatStringsSep "," cfg.cpu-manager-policy-options}\""} \
            ${optionalString (cfg.cpu-manager-reconcile-period != null) "--cpu-manager-reconcile-period ${toString cfg.cpu-manager-reconcile-period}"} \
            ${optionalString (cfg.enable-controller-attach-detach != null) "--enable-controller-attach-detach ${boolToString cfg.enable-controller-attach-detach}"} \
            ${optionalString (cfg.enable-debugging-handlers != null) "--enable-debugging-handlers ${boolToString cfg.enable-debugging-handlers}"} \
            ${optionalString (cfg.enable-load-reader != null) "--enable-load-reader"} \
              ${optionalString (cfg.enable-server != null) "--enable-server ${toString cfg.enable-server}"} \
            ${optionalString (cfg.enforce-node-allocatable != null) "--enforce-node-allocatable ${concatStringsSep "," cfg.enforce-node-allocatable}\""} \
            ${optionalString (cfg.event-burst != null) "--event-burst ${toString cfg.event-burst}"} \
            ${optionalString (cfg.event-qps != null) "--event-qps ${toString cfg.event-qps}"} \
            ${optionalString (cfg.event-storage-age-limit != null) "--event-storage-age-limit ${toString cfg.event-storage-age-limit}"} \
            ${optionalString (cfg.event-storage-event-limit != null) "--event-storage-event-limit ${toString cfg.event-storage-event-limit}"} \
            ${optionalString (cfg.eviction-hard != null) "--eviction-hard \"${concatStringsSep "," cfg.eviction-hard}\""} \
            ${optionalString (cfg.eviction-max-pod-grace-period != null) "--eviction-max-pod-grace-period ${toString cfg.eviction-max-pod-grace-period}"} \
            ${optionalString (cfg.eviction-minimum-reclaim != null) "--eviction-minimum-reclaim \"${concatStringsSep "," cfg.eviction-minimum-reclaim}\""} \
            ${optionalString (cfg.eviction-pressure-transition-period != null) "--eviction-pressure-transition-period ${toString cfg.eviction-pressure-transition-period}"} \
            ${optionalString (cfg.eviction-soft != null) "--eviction-soft \"${concatStringsSep "," cfg.eviction-soft}\""} \
            ${optionalString (cfg.eviction-soft-grace-period != null) "--eviction-soft-grace-period \"${concatStringsSep "," cfg.eviction-soft-grace-period}\""} \
            ${optionalString (cfg.exit-on-lock-contention != null) "--exit-on-lock-contention"} \
            ${optionalString (cfg.experimental-allocatable-ignore-eviction != null) "--experimental-allocatable-ignore-eviction ${boolToString cfg.experimental-allocatable-ignore-eviction}"} \
            ${optionalString (cfg.experimental-mounter-path != null) "--experimental-mounter-path ${toString cfg.experimental-mounter-path}"} \
            ${optionalString (cfg.fail-swap-on != null) "--fail-swap-on ${toString cfg.fail-swap-on}"} \
            ${optionalString (cfg.feature-gates != null) "--feature-gates \"${concatStringsSep "," cfg.feature-gates}\""} \
            ${optionalString (cfg.file-check-frequency != null) "--file-check-frequency ${toString cfg.file-check-frequency}"} \
            ${optionalString (cfg.global-housekeeping-interval != null) "--global-housekeeping-interval ${toString cfg.global-housekeeping-interval}"} \
            ${optionalString (cfg.hairpin-mode != null) "--hairpin-mode ${toString cfg.hairpin-mode}"} \
            ${optionalString (cfg.healthz-bind-address != null) "--healthz-bind-address ${toString cfg.healthz-bind-address}"} \
            ${optionalString (cfg.healthz-port != null) "--healthz-port ${toString cfg.healthz-port}"} \
            ${optionalString (cfg.hostname-override != null) "--hostname-override ${toString cfg.hostname-override}"} \
            ${optionalString (cfg.housekeeping-interval != null) "--housekeeping-interval ${toString cfg.housekeeping-interval}"} \
            ${optionalString (cfg.http-check-frequency != null) "--http-check-frequency ${toString cfg.http-check-frequency}"} \
            ${optionalString (cfg.image-credential-provider-bin-dir != null) "--image-credential-provider-bin-dir ${toString cfg.image-credential-provider-bin-dir}"} \
            ${optionalString (cfg.image-credential-provider-config != null) "--image-credential-provider-config ${toString cfg.image-credential-provider-config}"} \
            ${optionalString (cfg.image-gc-high-threshold != null) "--image-gc-high-threshold ${toString cfg.image-gc-high-threshold}"} \
            ${optionalString (cfg.image-gc-low-threshold != null) "--image-gc-low-threshold ${toString cfg.image-gc-low-threshold}"} \
            ${optionalString (cfg.image-service-endpoint != null) "--image-service-endpoint ${toString cfg.image-service-endpoint}"} \
            ${optionalString (cfg.keep-terminated-pod-volumes != null) "--keep-terminated-pod-volumes"} \
            ${optionalString (cfg.kernel-memcg-notification != null) "--kernel-memcg-notification ${toString cfg.kernel-memcg-notification}"} \
            ${optionalString (cfg.kube-api-burst != null) "--kube-api-burst ${toString cfg.kube-api-burst}"} \
            ${optionalString (cfg.kube-api-content-type != null) "--kube-api-content-type ${toString cfg.kube-api-content-type}"} \
            ${optionalString (cfg.kube-api-qps != null) "--kube-api-qps ${toString cfg.kube-api-qps}"} \
            ${optionalString (cfg.kube-reserved != null) "--kube-reserved \"${concatStringsSep "," cfg.kube-reserved}\""} \
            ${optionalString (cfg.kube-reserved-cgroup != null) "--kube-reserved-cgroup ${toString cfg.kube-reserved-cgroup}"} \
            ${optionalString (cfg.kubeconfig != null) "--kubeconfig ${toString cfg.kubeconfig}"} \
            ${optionalString (cfg.kubelet-cgroups != null) "--kubelet-cgroups ${toString cfg.kubelet-cgroups}"} \
            ${optionalString (cfg.local-storage-capacity-isolation != null) "--local-storage-capacity-isolation ${boolToString cfg.local-storage-capacity-isolation}"} \
            ${optionalString (cfg.lock-file != null) "--lock-file ${toString cfg.lock-file}"} \
            ${optionalString (cfg.log-cadvisor-usage != null) "--log-cadvisor-usage"} \
            ${optionalString (cfg.log-flush-frequency != null) "--log-flush-frequency ${toString cfg.log-flush-frequency}"} \
            ${optionalString (cfg.log-json-info-buffer-size != null) "--log-json-info-buffer-size ${toString cfg.log-json-info-buffer-size}"} \
            ${optionalString (cfg.log-json-split-stream != null) "--log-json-split-stream"} \
            ${optionalString (cfg.logging-format != null) "--logging-format ${toString cfg.logging-format}"} \
            ${optionalString (cfg.machine-id-file != null) "--machine-id-file \"${concatStringsSep "," cfg.machine-id-file}\""} \
            ${optionalString (cfg.make-iptables-util-chains != null) "--make-iptables-util-chains ${boolToString cfg.make-iptables-util-chains}"} \
            ${optionalString (cfg.manifest-url != null) "--manifest-url ${toString cfg.manifest-url}"} \
            ${optionalString (cfg.manifest-url-header != null) "--manifest-url-header \"${concatStringsSep "," cfg.manifest-url-header}\""} \
            ${optionalString (cfg.max-open-files != null) "--max-open-files ${toString cfg.max-open-files}"} \
            ${optionalString (cfg.max-pods != null) "--max-pods ${toString cfg.max-pods}"} \
            ${optionalString (cfg.maximum-dead-containers != null) "--maximum-dead-containers ${toString cfg.maximum-dead-containers}"} \
            ${optionalString (cfg.maximum-dead-containers-per-container != null) "--maximum-dead-containers-per-container ${toString cfg.maximum-dead-containers-per-container}"} \
            ${optionalString (cfg.memory-manager-policy != null) "--memory-manager-policy ${toString cfg.memory-manager-policy}"} \
            ${optionalString (cfg.minimum-container-ttl-duration != null) "--minimum-container-ttl-duration ${toString cfg.minimum-container-ttl-duration}"} \
            ${optionalString (cfg.minimum-image-ttl-duration != null) "--minimum-image-ttl-duration ${toString cfg.minimum-image-ttl-duration}"} \
            ${optionalString (cfg.node-ip != null) "--node-ip ${toString cfg.node-ip}"} \
            ${optionalString (cfg.node-labels != null) "--node-labels ${toString cfg.node-labels}"} \
            ${optionalString (cfg.node-status-max-images != null) "--node-status-max-images ${toString cfg.node-status-max-images}"} \
            ${optionalString (cfg.node-status-update-frequency != null) "--node-status-update-frequency ${toString cfg.node-status-update-frequency}"} \
            ${optionalString (cfg.oom-score-adj != null) "--oom-score-adj ${toString cfg.oom-score-adj}"} \
            ${optionalString (cfg.pod-cidr != null) "--pod-cidr ${toString cfg.pod-cidr}"} \
            ${optionalString (cfg.pod-infra-container-image != null) "--pod-infra-container-image ${toString cfg.pod-infra-container-image}"} \
            ${optionalString (cfg.pod-manifest-path != null) "--pod-manifest-path ${toString cfg.pod-manifest-path}"} \
            ${optionalString (cfg.pod-max-pids != null) "--pod-max-pids ${toString cfg.pod-max-pids}"} \
            ${optionalString (cfg.pods-per-core != null) "--pods-per-core ${toString cfg.pods-per-core}"} \
            ${optionalString (cfg.port != null) "--port ${toString cfg.port}"} \
            ${optionalString (cfg.protect-kernel-defaults != null) "--protect-kernel-defaults"} \
            ${optionalString (cfg.provider-id != null) "--provider-id ${toString cfg.provider-id}"} \
            ${optionalString (cfg.qos-reserved != null) "--qos-reserved \"${concatStringsSep "," cfg.qos-reserved}\""} \
            ${optionalString (cfg.read-only-port != null) "--read-only-port ${toString cfg.read-only-port}"} \
            ${optionalString (cfg.register-node != null) "--register-node"} \
            ${optionalString (cfg.register-schedulable != null) "--register-schedulable ${boolToString cfg.register-schedulable}"} \
            ${optionalString (cfg.register-with-taints != null) "--register-with-taints \"${concatStringsSep "," cfg.register-with-taints}\""} \
            ${optionalString (cfg.registry-burst != null) "--registry-burst ${toString cfg.registry-burst}"} \
            ${optionalString (cfg.registry-qps != null) "--registry-qps ${toString cfg.registry-qps}"} \
            ${optionalString (cfg.reserved-cpus != null) "--reserved-cpus \"${concatStringsSep "," cfg.reserved-cpus}\""} \
            ${optionalString (cfg.reserved-memory != null) "--reserved-memory \"${concatStringsSep "," cfg.reserved-memory}\""} \
            ${optionalString (cfg.resolv-conf != null) "--resolv-conf ${toString cfg.resolv-conf}"} \
            ${optionalString (cfg.root-dir != null) "--root-dir ${toString cfg.root-dir}"} \
            ${optionalString (cfg.rotate-certificates != null) "--rotate-certificates"} \
            ${optionalString (cfg.rotate-server-certificates != null) "--rotate-server-certificates"} \
            ${optionalString (cfg.runonce != null) "--runonce ${boolToString cfg.runonce}"} \
            ${optionalString (cfg.runtime-cgroups != null) "--runtime-cgroups ${toString cfg.runtime-cgroups}"} \
            ${optionalString (cfg.runtime-request-timeout != null) "--runtime-request-timeout ${toString cfg.runtime-request-timeout}"} \
            ${optionalString (cfg.seccomp-default != null) "--seccomp-default"} \
            ${optionalString (cfg.serialize-image-pulls != null) "--serialize-image-pulls"} \
            ${optionalString (cfg.storage-driver-buffer-duration != null) "--storage-driver-buffer-duration ${toString cfg.storage-driver-buffer-duration}"} \
            ${optionalString (cfg.storage-driver-db != null) "--storage-driver-db ${toString cfg.storage-driver-db}"} \
            ${optionalString (cfg.storage-driver-host != null) "--storage-driver-host ${toString cfg.storage-driver-host}"} \
            ${optionalString (cfg.storage-driver-password != null) "--storage-driver-password ${toString cfg.storage-driver-password}"} \
            ${optionalString (cfg.storage-driver-secure != null) "--storage-driver-secure"} \
            ${optionalString (cfg.storage-driver-table != null) "--storage-driver-table ${toString cfg.storage-driver-table}"} \
            ${optionalString (cfg.storage-driver-user != null) "--storage-driver-user ${toString cfg.storage-driver-user}"} \
            ${optionalString (cfg.streaming-connection-idle-timeout != null) "--streaming-connection-idle-timeout ${toString cfg.streaming-connection-idle-timeout}"} \
            ${optionalString (cfg.sync-frequency != null) "--sync-frequency ${toString cfg.sync-frequency}"} \
            ${optionalString (cfg.system-cgroups != null) "--system-cgroups ${toString cfg.system-cgroups}"} \
            ${optionalString (cfg.system-reserved != null) "--system-reserved \"${concatStringsSep "," cfg.system-reserved}\""} \
            ${optionalString (cfg.system-reserved-cgroup != null) "--system-reserved-cgroup ${toString cfg.system-reserved-cgroup}"} \
            ${optionalString (cfg.tls-cert-file != null) "--tls-cert-file ${toString cfg.tls-cert-file}"} \
            ${optionalString (cfg.tls-cipher-suites != null) "---tls-cipher-suites \"${concatStringsSep "," cfg.tls-cipher-suites}\""} \
            ${optionalString (cfg.tls-min-version != null) "--tls-min-version ${toString cfg.tls-min-version}"} \
            ${optionalString (cfg.tls-private-key-file != null) "--tls-private-key-file ${toString cfg.tls-private-key-file}"} \
            ${optionalString (cfg.topology-manager-policy != null) "--topology-manager-policy ${toString cfg.topology-manager-policy}"} \
            ${optionalString (cfg.topology-manager-policy-options != null) "--topology-manager-policy-options \"${concatStringsSep "," cfg.topology-manager-policy-options}\""} \
            ${optionalString (cfg.topology-manager-scope != null) "--topology-manager-scope ${toString cfg.topology-manager-scope}"} \
            ${optionalString (cfg.v != null) "--v ${toString cfg.v}"} \
            ${optionalString (cfg.vmodule != null) "--vmodule \"${concatStringsSep "," cfg.vmodule}\""} \
            ${optionalString (cfg.volume-plugin-dir != null) "--volume-plugin-dir ${toString cfg.volume-plugin-dir}"} \
            ${optionalString (cfg.volume-stats-agg-period != null) "--volume-stats-agg-period ${toString cfg.volume-stats-agg-period}"}
        '';
      };
      unitConfig = {
        StartLimitIntervalSec = 0;
      };
    };
  };
}
