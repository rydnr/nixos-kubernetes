{
  config,
  pkgs,
  lib,
  ...
}:

with lib;

let
  cfg = config.services.kube-controller-manager;
  boolToString = b: if b then "true" else "false";
in
{
  options.services.kube-controller-manager = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "The Kubernetes controller manager is a daemon that embeds the core control loops shipped with Kubernetes. In applications of robotics and automation, a control loop is a non-terminating loop that regulates the state of the system. In Kubernetes, a controller is a control loop that watches the shared state of the cluster through the apiserver and makes changes attempting to move the current state towards the desired state. Examples of controllers that ship with Kubernetes today are the replication controller, endpoints controller, namespace controller, and serviceaccounts controller.";
    };

    contention-profiling = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable block profiling, if profiling is enabled";
    };

    profiling = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable profiling via web interface host:port/debug/pprof/ (default true)";
    };

    enable-leader-migration = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Whether to enable controller leader migration.";
    };

    leader-migration-config = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the config file for controller leader migration, or empty to use the value that reflects default configuration of the controller manager. The config file should be of type LeaderMigrationConfiguration, group controllermanager.config.k8s.io, version v1alpha1.";
    };

    allocate-node-cidrs = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Should CIDRs for Pods be allocated and set on the cloud provider.";
    };

    cidr-allocator-type = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Type of CIDR allocator to use (default 'RangeAllocator')";
    };

    cloud-config = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The path to the cloud provider configuration file. Empty string for no configuration file.";
    };

    cloud-provider = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The provider for cloud services. Empty string for no provider.";
    };

    cluster-cidr = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "CIDR Range for Pods in cluster. Requires --allocate-node-cidrs to be true";
    };

    cluster-name = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The instance prefix for the cluster. (default 'kubernetes')";
    };

    configure-cloud-routes = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Should CIDRs allocated by allocate-node-cidrs be configured on the cloud provider. (default true)";
    };

    controller-start-interval = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Interval between starting controller managers.";
    };

    controllers = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A list of controllers to enable. '*' enables all on-by-default controllers, 'foo' enables the controller named 'foo', '-foo' disables the controller named 'foo'.";
    };

    external-cloud-volume-plugin = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The plugin to use when cloud provider is set to external. Can be empty, should only be set when cloud-provider is external. Currently used to allow node-ipam-controller, persistentvolume-binder-controller, persistentvolume-expander-controller and attach-detach-controller to work for in tree cloud providers.";
    };

    feature-gates = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = """
A set of key=value pairs that describe feature gates for alpha/experimental features. Options are:
  APIListChunking=true|false (BETA - default=true)
  APIPriorityAndFairness=true|false (BETA - default=true)
  APIResponseCompression=true|false (BETA - default=true)
  APIServerIdentity=true|false (BETA - default=true)
  APIServerTracing=true|false (BETA - default=true)
  AdmissionWebhookMatchConditions=true|false (BETA - default=true)
  AggregatedDiscoveryEndpoint=true|false (BETA - default=true)
  AllAlpha=true|false (ALPHA - default=false)
  AllBeta=true|false (BETA - default=false)
  AnyVolumeDataSource=true|false (BETA - default=true)
  AppArmor=true|false (BETA - default=true)
  CPUManagerPolicyAlphaOptions=true|false (ALPHA - default=false)
  CPUManagerPolicyBetaOptions=true|false (BETA - default=true)
  CPUManagerPolicyOptions=true|false (BETA - default=true)
  CRDValidationRatcheting=true|false (ALPHA - default=false)
  CSIMigrationPortworx=true|false (BETA - default=false)
  CSINodeExpandSecret=true|false (BETA - default=true)
  CSIVolumeHealth=true|false (ALPHA - default=false)
  CloudControllerManagerWebhook=true|false (ALPHA - default=false)
  CloudDualStackNodeIPs=true|false (ALPHA - default=false)
  ClusterTrustBundle=true|false (ALPHA - default=false)
  ComponentSLIs=true|false (BETA - default=true)
  ConsistentListFromCache=true|false (ALPHA - default=false)
  ContainerCheckpoint=true|false (ALPHA - default=false)
  ContextualLogging=true|false (ALPHA - default=false)
  CronJobsScheduledAnnotation=true|false (BETA - default=true)
  CrossNamespaceVolumeDataSource=true|false (ALPHA - default=false)
  CustomCPUCFSQuotaPeriod=true|false (ALPHA - default=false)
  CustomResourceValidationExpressions=true|false (BETA - default=true)
  DevicePluginCDIDevices=true|false (ALPHA - default=false)
  DisableCloudProviders=true|false (ALPHA - default=false)
  DisableKubeletCloudCredentialProviders=true|false (ALPHA - default=false)
  DynamicResourceAllocation=true|false (ALPHA - default=false)
  ElasticIndexedJob=true|false (BETA - default=true)
  EventedPLEG=true|false (ALPHA - default=false)
  GracefulNodeShutdown=true|false (BETA - default=true)
  GracefulNodeShutdownBasedOnPodPriority=true|false (BETA - default=true)
  HPAContainerMetrics=true|false (BETA - default=true)
  HPAScaleToZero=true|false (ALPHA - default=false)
  HonorPVReclaimPolicy=true|false (ALPHA - default=false)
  InPlacePodVerticalScaling=true|false (ALPHA - default=false)
  InTreePluginAWSUnregister=true|false (ALPHA - default=false)
  InTreePluginAzureDiskUnregister=true|false (ALPHA - default=false)
  InTreePluginAzureFileUnregister=true|false (ALPHA - default=false)
  InTreePluginGCEUnregister=true|false (ALPHA - default=false)
  InTreePluginOpenStackUnregister=true|false (ALPHA - default=false)
  InTreePluginPortworxUnregister=true|false (ALPHA - default=false)
  InTreePluginvSphereUnregister=true|false (ALPHA - default=false)
  JobBackoffLimitPerIndex=true|false (ALPHA - default=false)
  JobPodFailurePolicy=true|false (BETA - default=true)
  JobPodReplacementPolicy=true|false (ALPHA - default=false)
  JobReadyPods=true|false (BETA - default=true)
  KMSv2=true|false (BETA - default=true)
  KMSv2KDF=true|false (BETA - default=false)
  KubeProxyDrainingTerminatingNodes=true|false (ALPHA - default=false)
  KubeletCgroupDriverFromCRI=true|false (ALPHA - default=false)
  KubeletInUserNamespace=true|false (ALPHA - default=false)
  KubeletPodResourcesDynamicResources=true|false (ALPHA - default=false)
  KubeletPodResourcesGet=true|false (ALPHA - default=false)
  KubeletTracing=true|false (BETA - default=true)
  LegacyServiceAccountTokenCleanUp=true|false (ALPHA - default=false)
  LocalStorageCapacityIsolationFSQuotaMonitoring=true|false (ALPHA - default=false)
  LogarithmicScaleDown=true|false (BETA - default=true)
  LoggingAlphaOptions=true|false (ALPHA - default=false)
  LoggingBetaOptions=true|false (BETA - default=true)
  MatchLabelKeysInPodTopologySpread=true|false (BETA - default=true)
  MaxUnavailableStatefulSet=true|false (ALPHA - default=false)
  MemoryManager=true|false (BETA - default=true)
  MemoryQoS=true|false (ALPHA - default=false)
  MinDomainsInPodTopologySpread=true|false (BETA - default=true)
  MultiCIDRRangeAllocator=true|false (ALPHA - default=false)
  MultiCIDRServiceAllocator=true|false (ALPHA - default=false)
  NewVolumeManagerReconstruction=true|false (BETA - default=true)
  NodeInclusionPolicyInPodTopologySpread=true|false (BETA - default=true)
  NodeLogQuery=true|false (ALPHA - default=false)
  NodeSwap=true|false (BETA - default=false)
  OpenAPIEnums=true|false (BETA - default=true)
  PDBUnhealthyPodEvictionPolicy=true|false (BETA - default=true)
  PersistentVolumeLastPhaseTransitionTime=true|false (ALPHA - default=false)
  PodAndContainerStatsFromCRI=true|false (ALPHA - default=false)
  PodDeletionCost=true|false (BETA - default=true)
  PodDisruptionConditions=true|false (BETA - default=true)
  PodHostIPs=true|false (ALPHA - default=false)
  PodIndexLabel=true|false (BETA - default=true)
  PodReadyToStartContainersCondition=true|false (ALPHA - default=false)
  PodSchedulingReadiness=true|false (BETA - default=true)
  ProcMountType=true|false (ALPHA - default=false)
  QOSReserved=true|false (ALPHA - default=false)
  ReadWriteOncePod=true|false (BETA - default=true)
  RecoverVolumeExpansionFailure=true|false (ALPHA - default=false)
  RemainingItemCount=true|false (BETA - default=true)
  RotateKubeletServerCertificate=true|false (BETA - default=true)
  SELinuxMountReadWriteOncePod=true|false (BETA - default=true)
  SchedulerQueueingHints=true|false (BETA - default=false)
  SecurityContextDeny=true|false (ALPHA - default=false)
  SeparateCacheWatchRPC=true|false (BETA - default=true)
  ServiceNodePortStaticSubrange=true|false (BETA - default=true)
  SidecarContainers=true|false (ALPHA - default=false)
  SizeMemoryBackedVolumes=true|false (BETA - default=true)
  SkipReadOnlyValidationGCE=true|false (ALPHA - default=false)
  StableLoadBalancerNodeSet=true|false (BETA - default=true)
  StatefulSetAutoDeletePVC=true|false (BETA - default=true)
  StatefulSetStartOrdinal=true|false (BETA - default=true)
  StorageVersionAPI=true|false (ALPHA - default=false)
  StorageVersionHash=true|false (BETA - default=true)
  TopologyAwareHints=true|false (BETA - default=true)
  TopologyManagerPolicyAlphaOptions=true|false (ALPHA - default=false)
  TopologyManagerPolicyBetaOptions=true|false (BETA - default=true)
  TopologyManagerPolicyOptions=true|false (BETA - default=true)
  UnauthenticatedHTTP2DOSMitigation=true|false (BETA - default=false)
  UnknownVersionInteroperabilityProxy=true|false (ALPHA - default=false)
  UserNamespacesSupport=true|false (ALPHA - default=false)
  ValidatingAdmissionPolicy=true|false (BETA - default=false)
  VolumeCapacityPriority=true|false (ALPHA - default=false)
  WatchFromStorageWithoutResourceVersion=true|false (BETA - default=false)
  WatchList=true|false (ALPHA - default=false)
  WinDSR=true|false (ALPHA - default=false)
  WinOverlay=true|false (BETA - default=true)
  WindowsHostNetwork=true|false (ALPHA - default=true)
""";
    };

    kube-api-burst = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Burst to use while talking with kubernetes apiserver. (default 30)";
    };

    kube-api-content-type = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "string             Content type of requests sent to apiserver. (default "application/vnd.kubernetes.protobuf")";
    };

    kube-api-qps = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "QPS to use while talking with kubernetes apiserver. (default 20)";
    };

    leader-elect = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Start a leader election client and gain leadership before executing the main loop. Enable this when running replicated components for high availability. (default true)";
    };

    leader-elect-lease-duration = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration that non-leader candidates will wait after observing a leadership renewal until attempting to acquire leadership of a led but unrenewed leader slot. This is effectively the maximum duration that a leader can be stopped before it is replaced by another candidate. This is only applicable if leader election is enabled. (default 15s)";
    };

    leader-elect-renew-deadline = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The interval between attempts by the acting master to renew a leadership slot before it stops leading. This must be less than the lease duration. This is only applicable if leader election is enabled. (default 10s)";
    };

    leader-elect-resource-lock = mkOption {
      type = types.nullOr (types.enum [ "leases" "endpointsleases" "configmapsleases" ]);
      default = null;
      description = "The type of resource object that is used for locking during leader election. Supported options are 'leases', 'endpointsleases' and 'configmapsleases'. (default 'leases')";
    };

    leader-elect-resource-name = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The name of resource object that is used for locking during leader election. (default 'kube-controller-manager')";
    };

    leader-elect-resource-namespace = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The namespace of resource object that is used for locking during leader election. (default 'kube-system')";
    };

    leader-elect-retry-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration the clients should wait between attempting acquisition and renewal of a leadership. This is only applicable if leader election is enabled. (default 2s)";
    };

    min-resync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The resync period in reflectors will be random between MinResyncPeriod and 2*MinResyncPeriod. (default 12h0m0s)";
    };

    node-monitor-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period for syncing NodeStatus in cloud-node-lifecycle-controller. (default 5s)";
    };

    route-reconciliation-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period for reconciling routes created for Nodes by cloud provider. (default 10s)";
    };

    use-service-account-credentials = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, use individual service account credentials for each controller.";
    };

    concurrent-service-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of services that are allowed to sync concurrently. Larger number = more responsive service management, but more CPU (and network) load (default 1)";
    };

    bind-address = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address on which to listen for the --secure-port port. The associated interface(s) must be reachable by the rest of the cluster, and by CLI/web clients. If blank or an unspecified address (0.0.0.0 or ::), all interfaces and IP address families will be used. (default 0.0.0.0)";
    };

    cert-dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The directory where the TLS certs are located. If --tls-cert-file and --tls-private-key-file are provided, this flag will be ignored.";
    };

    http2-max-streams-per-connection = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The limit that the server gives to clients for the maximum number of streams in an HTTP/2 connection. Zero means to use golang's default.";
    };

    permit-address-sharing = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, SO_REUSEADDR will be used when binding the port. This allows binding to wildcard IPs like 0.0.0.0 and specific IPs in parallel, and it avoids waiting for the kernel to release sockets in TIME_WAIT state. [default=false]";
    };

    permit-port-sharing = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, SO_REUSEPORT will be used when binding the port, which allows more than one instance to bind on the same address and port. [default=false]";
    };

    secure-port = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The port on which to serve HTTPS with authentication and authorization. If 0, don't serve HTTPS at all. (default 10257)";
    };

    tls-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert). If HTTPS serving is enabled, and --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to the directory specified by --cert-dir.";
    };

    tls-cipher-suites = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of cipher suites for the server. If omitted, the default Go cipher suites will be used. ";
    };

    tls-min-version = mkOption {
      type = types.nullOr (types.enum [ "VersionTLS10" "VersionTLS11" "VersionTLS12" "VersionTLS13" ]);
      default = null;
      description = "Minimum TLS version supported. Possible values: VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13";
    };

    tls-private-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File containing the default x509 private key matching --tls-cert-file.";
    };

    tls-sni-cert-key = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A pair of x509 certificate and private key file paths, optionally suffixed with a list of domain patterns which are fully qualified domain names, possibly with prefixed wildcard segments. The domain patterns also allow IP addresses, but IPs should only be used if the apiserver has visibility to the IP address requested by a client. If no domain patterns are provided, the names of the certificate are extracted. Non-wildcard matches trump over wildcard matches, explicit domain patterns trump over extracted names. For multiple key/certificate pairs, use the --tls-sni-cert-key multiple times. Examples: 'example.crt,example.key' or 'foo.crt,foo.key:*.foo.com,foo.com'. (default [])";
    };

    authentication-kubeconfig = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "kubeconfig file pointing at the 'core' kubernetes server with enough rights to create tokenreviews.authentication.k8s.io. This is optional. If empty, all token requests are considered to be anonymous and no client CA is looked up in the cluster.";
    };

    authentication-skip-lookup = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If false, the authentication-kubeconfig will be used to lookup missing authentication configuration from the cluster.";
    };

    authentication-token-webhook-cache-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache responses from the webhook token authenticator. (default 10s)";
    };

    authentication-tolerate-lookup-failure = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, failures to look up missing authentication configuration from the cluster are not considered fatal. Note that this can result in authentication that treats all requests as anonymous.";
    };

    client-ca-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.";
    };

    requestheader-allowed-names = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of client certificate common names to allow to provide usernames in headers specified by --requestheader-username-headers. If empty, any client certificate validated by the authorities in --requestheader-client-ca-file is allowed.";
    };

    requestheader-client-ca-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Root certificate bundle to use to verify client certificates on incoming requests before trusting usernames in headers specified by --requestheader-username-headers. WARNING: generally do not depend on authorization being already done for incoming requests.";
    };

    requestheader-extra-headers-prefix = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of request header prefixes to inspect. X-Remote-Extra- is suggested. (default [x-remote-extra-])";
    };

    requestheader-group-headers = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of request headers to inspect for groups. X-Remote-Group is suggested. (default [x-remote-group])";
    };

    requestheader-username-headers = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of request headers to inspect for usernames. X-Remote-User is common. (default [x-remote-user])";
    };

    authorization-always-allow-paths = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A list of HTTP paths to skip during authorization, i.e. these are authorized without contacting the 'core' kubernetes server. (default [/healthz,/readyz,/livez])";
    };

    authorization-kubeconfig = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "kubeconfig file pointing at the 'core' kubernetes server with enough rights to create subjectaccessreviews.authorization.k8s.io. This is optional. If empty, all requests not skipped by authorization are forbidden.";
    };

    authorization-webhook-cache-authorized-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache 'authorized' responses from the webhook authorizer. (default 10s)";
    };

    authorization-webhook-cache-unauthorized-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache 'unauthorized' responses from the webhook authorizer. (default 10s)";
    };

    attach-detach-reconcile-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The reconciler sync wait time between volume attach detach. This duration must be larger than one second, and increasing this value from the default may allow for volumes to be mismatched with pods. (default 1m0s)";
    };

    disable-attach-detach-reconcile-sync = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Disable volume attach detach reconciler sync. Disabling this may cause volumes to be mismatched with pods. Use wisely.";
    };

    cluster-signing-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded X509 CA certificate used to issue cluster-scoped certificates.  If specified, no more specific --cluster-signing-* flag may be specified.";
    };

    cluster-signing-duration = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The max length of duration signed certificates will be given.  Individual CSRs may request shorter certs by setting spec.expirationSeconds. (default 8760h0m0s)";
    };

    cluster-signing-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded RSA or ECDSA private key used to sign cluster-scoped certificates.  If specified, no more specific --cluster-signing-* flag may be specified.";
    };

    cluster-signing-kube-apiserver-client-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded X509 CA certificate used to issue certificates for the kubernetes.io/kube-apiserver-client signer.  If specified, --cluster-signing-{cert,key}-file must not be set.";
    };

    cluster-signing-kube-apiserver-client-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded RSA or ECDSA private key used to sign certificates for the kubernetes.io/kube-apiserver-client signer.  If specified, --cluster-signing-{cert,key}-file must not be set.";
    };

    cluster-signing-kubelet-client-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded X509 CA certificate used to issue certificates for the kubernetes.io/kube-apiserver-client-kubelet signer.  If specified, --cluster-signing-{cert,key}-file must not be set.";
    };

    cluster-signing-kubelet-client-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "pathFilename containing a PEM-encoded RSA or ECDSA private key used to sign certificates for the kubernetes.io/kube-apiserver-client-kubelet signer.  If specified, --cluster-signing-{cert,key}-file must not be set.";
    };

    cluster-signing-kubelet-serving-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded X509 CA certificate used to issue certificates for the kubernetes.io/kubelet-serving signer.  If specified, --cluster-signing-{cert,key}-file must not be set.";
    };

    cluster-signing-kubelet-serving-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded RSA or ECDSA private key used to sign certificates for the kubernetes.io/kubelet-serving signer.  If specified, --cluster-signing-{cert,key}-file must not be set.";
    };

    cluster-signing-legacy-unknown-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded X509 CA certificate used to issue certificates for the kubernetes.io/legacy-unknown signer.  If specified, --cluster-signing-{cert,key}-file must not be set.";
    };

    cluster-signing-legacy-unknown-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded RSA or ECDSA private key used to sign certificates for the kubernetes.io/legacy-unknown signer.  If specified, --cluster-signing-{cert,key}-file must not be set.";
    };

    concurrent-deployment-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of deployment objects that are allowed to sync concurrently. Larger number = more responsive deployments, but more CPU (and network) load (default 5)";
    };

    concurrent-statefulset-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of statefulset objects that are allowed to sync concurrently. Larger number = more responsive statefulsets, but more CPU (and network) load (default 5)";
    };

    concurrent-endpoint-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of endpoint syncing operations that will be done concurrently. Larger number = faster endpoint updating, but more CPU (and network) load (default 5)";
    };

    endpoint-updates-batch-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The length of endpoint updates batching period. Processing of pod changes will be delayed by this duration to join them with potential upcoming updates and reduce the overall number of endpoints updates. Larger number = higher endpoint programming latency, but lower number of endpoints revision generated";
    };

    concurrent-service-endpoint-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of service endpoint syncing operations that will be done concurrently. Larger number = faster endpoint slice updating, but more CPU (and network) load. Defaults to 5. (default 5)";
    };

    endpointslice-updates-batch-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The length of endpoint slice updates batching period. Processing of pod changes will be delayed by this duration to join them with potential upcoming updates and reduce the overall number of endpoints updates. Larger number = higher endpoint programming latency, but lower number of endpoints revision generated";
    };

    max-endpoints-per-slice = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The maximum number of endpoints that will be added to an EndpointSlice. More endpoints per slice will result in less endpoint slices, but larger resources. Defaults to 100. (default 100)";
    };

    mirroring-concurrent-service-endpoint-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of service endpoint syncing operations that will be done concurrently by the endpointslice-mirroring-controller. Larger number = faster endpoint slice updating, but more CPU (and network) load. Defaults to 5. (default 5)";
    };

    mirroring-endpointslice-updates-batch-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The length of EndpointSlice updates batching period for endpointslice-mirroring-controller. Processing of EndpointSlice changes will be delayed by this duration to join them with potential upcoming updates and reduce the overall number of EndpointSlice updates. Larger number = higher endpoint programming latency, but lower number of endpoints revision generated";
    };

    mirroring-max-endpoints-per-subset = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The maximum number of endpoints that will be added to an EndpointSlice by the endpointslice-mirroring-controller. More endpoints per slice will result in less endpoint slices, but larger resources. Defaults to 100. (default 1000)";
    };

    concurrent-ephemeralvolume-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of ephemeral volume syncing operations that will be done concurrently. Larger number = faster ephemeral volume updating, but more CPU (and network) load (default 5)";
    };

    concurrent-gc-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of garbage collector workers that are allowed to sync concurrently. (default 20)";
    };

    enable-garbage-collector = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enables the generic garbage collector. MUST be synced with the corresponding flag of the kube-apiserver. (default true)";
    };

    concurrent-horizontal-pod-autoscaler-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of horizontal pod autoscaler objects that are allowed to sync concurrently. Larger number = more responsive horizontal pod autoscaler objects processing, but more CPU (and network) load. (default 5)";
    };

    horizontal-pod-autoscaler-cpu-initialization-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period after pod start when CPU samples might be skipped. (default 5m0s)";
    };

    horizontal-pod-autoscaler-downscale-stabilization = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period for which autoscaler will look backwards and not scale down below any recommendation it made during that period. (default 5m0s)";
    };

    horizontal-pod-autoscaler-initial-readiness-delay = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period after pod start during which readiness changes will be treated as initial readiness. (default 30s)";
    };

    horizontal-pod-autoscaler-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period for syncing the number of pods in horizontal pod autoscaler. (default 15s)";
    };

    horizontal-pod-autoscaler-tolerance = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "The minimum change (from 1.0) in the desired-to-actual metrics ratio for the horizontal pod autoscaler to consider scaling. (default 0.1)";
    };

    concurrent-job-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of job objects that are allowed to sync concurrently. Larger number = more responsive jobs, but more CPU (and network) load (default 5)";
    };

    concurrent-cron-job-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of cron job objects that are allowed to sync concurrently. Larger number = more responsive jobs, but more CPU (and network) load (default 5)";
    };

    legacy-service-account-token-clean-up-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period of time since the last usage of an legacy service account token before it can be deleted. (default 8760h0m0s)";
    };

    concurrent-namespace-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of namespace objects that are allowed to sync concurrently. Larger number = more responsive namespace termination, but more CPU (and network) load (default 10)";
    };

    namespace-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period for syncing namespace life-cycle updates (default 5m0s)";
    };

    node-cidr-mask-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Mask size for node cidr in cluster. Default is 24 for IPv4 and 64 for IPv6.";
    };

    node-cidr-mask-size-ipv4 = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Mask size for IPv4 node cidr in dual-stack cluster. Default is 24.";
    };

    node-cidr-mask-size-ipv6 = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Mask size for IPv6 node cidr in dual-stack cluster. Default is 64.";
    };

    service-cluster-ip-range = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "CIDR Range for Services in cluster. Requires --allocate-node-cidrs to be true";
    };

    large-cluster-size-threshold = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Number of nodes from which node-lifecycle-controller treats the cluster as large for the eviction logic purposes. --secondary-node-eviction-rate is implicitly overridden to 0 for clusters this size or smaller. (default 50)";
    };

    node-eviction-rate = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "Number of nodes per second on which pods are deleted in case of node failure when a zone is healthy (see --unhealthy-zone-threshold for definition of healthy/unhealthy). Zone refers to entire cluster in non-multizone clusters. (default 0.1)";
    };

    node-monitor-grace-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Amount of time which we allow running Node to be unresponsive before marking it unhealthy. Must be N times more than kubelet's nodeStatusUpdateFrequency, where N means number of retries allowed for kubelet to post node status. (default 40s)";
    };

    node-startup-grace-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Amount of time which we allow starting Node to be unresponsive before marking it unhealthy. (default 1m0s)";
    };

    secondary-node-eviction-rate = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "Number of nodes per second on which pods are deleted in case of node failure when a zone is unhealthy (see --unhealthy-zone-threshold for definition of healthy/unhealthy). Zone refers to entire cluster in non-multizone clusters. This value is implicitly overridden to 0 if the cluster size is smaller than --large-cluster-size-threshold. (default 0.01)";
    };

    unhealthy-zone-threshold = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "Fraction of Nodes in a zone which needs to be not Ready (minimum 3) for zone to be treated as unhealthy.  (default 0.55)";
    };

    enable-dynamic-provisioning = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable dynamic provisioning for environments that support it. (default true)";
    };

    enable-hostpath-provisioner = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable HostPath PV provisioning when running without a cloud provider. This allows testing and development of provisioning features.  HostPath provisioning is not supported in any way, won't work in a multi-node cluster, and should not be used for anything other than testing or development.";
    };

    flex-volume-plugin-dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Full path of the directory in which the flex volume plugin should search for additional third party volume plugins. (default '/usr/libexec/kubernetes/kubelet-plugins/volume/exec/')";
    };

    pv-recycler-increment-timeout-nfs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The increment of time added per Gi to ActiveDeadlineSeconds for an NFS scrubber pod (default 30)";
    };

    pv-recycler-minimum-timeout-hostpath = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The minimum ActiveDeadlineSeconds to use for a HostPath Recycler pod.  This is for development and testing only and will not work in a multi-node cluster. (default 60)";
    };

    pv-recycler-minimum-timeout-nfs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The minimum ActiveDeadlineSeconds to use for an NFS Recycler pod (default 300)";
    };

    pv-recycler-pod-template-filepath-hostpath = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The file path to a pod definition used as a template for HostPath persistent volume recycling. This is for development and testing only and will not work in a multi-node cluster.";
    };

    pv-recycler-pod-template-filepath-nfs = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The file path to a pod definition used as a template for NFS persistent volume recycling";
    };

    pv-recycler-timeout-increment-hostpath = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The increment of time added per Gi to ActiveDeadlineSeconds for a HostPath scrubber pod.  This is for development and testing only and will not work in a multi-node cluster. (default 30)";
    };

    pvclaimbinder-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period for syncing persistent volumes and persistent volume claims (default 15s)";
    };

    terminated-pod-gc-threshold = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Number of terminated pods that can exist before the terminated pod garbage collector starts deleting terminated pods. If <= 0, the terminated pod garbage collector is disabled. (default 12500)";
    };

    concurrent-replicaset-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of replica sets that are allowed to sync concurrently. Larger number = more responsive replica management, but more CPU (and network) load (default 5)";
    };

    concurrent-rc-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of replication controllers that are allowed to sync concurrently. Larger number = more responsive replica management, but more CPU (and network) load (default 5)";
    };

    concurrent-resource-quota-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of resource quotas that are allowed to sync concurrently. Larger number = more responsive quota management, but more CPU (and network) load (default 5)";
    };

    resource-quota-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The period for syncing quota usage status in the system (default 5m0s)";
    };

    concurrent-serviceaccount-token-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of service account token objects that are allowed to sync concurrently. Larger number = more responsive token generation, but more CPU (and network) load (default 5)";
    };

    root-ca-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "If set, this root certificate authority will be included in service account's token secret. This must be a valid PEM-encoded CA bundle.";
    };

    service-account-private-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Filename containing a PEM-encoded private RSA or ECDSA key used to sign service account tokens.";
    };

    concurrent-ttl-after-finished-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of ttl-after-finished-controller workers that are allowed to sync concurrently. (default 5)";
    };

    concurrent-validating-admission-policy-status-syncs = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The number of ValidatingAdmissionPolicyStatusController workers that are allowed to sync concurrently. (default 5)";
    };

    allow-metric-labels = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "stringToString       The map from metric-label to value allow-list of this label. The key's format is <MetricName>,<LabelName>. The value's format is <allowed_value>,<allowed_value>...e.g. metric1,label1='v1,v2,v3', metric1,label2='v1,v2,v3' metric2,label1='v1,v2,v3'. (default [])";
    };

    disabled-metrics = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "This flag provides an escape hatch for misbehaving metrics. You must provide the fully qualified metric name in order to disable it. Disclaimer: disabling metrics is higher in precedence than showing hidden metrics.";
    };

    show-hidden-metrics-for-version = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The previous version for which you want to show hidden metrics. Only the previous minor version is meaningful, other values will not be allowed. The format is <major>.<minor>, e.g.: '1.16'. The purpose of this format is make sure you have the opportunity to notice if the next release hides additional metrics, rather than being surprised when they are permanently removed in the release after that.";
    };

    log-flush-frequency = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Maximum number of seconds between log flushes (default 5s)";
    };

    log-json-info-buffer-size = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "[Alpha] In JSON format with split output streams, the info messages can be buffered for a while to increase performance. The default value of zero bytes disables buffering. The size can be specified as number of bytes (512), multiples of 1000 (1K), multiples of 1024 (2Ki), or powers of those (3M, 4G, 5Mi, 6Gi). Enable the LoggingAlphaOptions feature gate to use this.";
    };

    log-json-split-stream = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "[Alpha] In JSON format, write error messages to stderr and info messages to stdout. The default is to write a single stream to stdout. Enable the LoggingAlphaOptions feature gate to use this.";
    };

    logging-format = mkOption {
      type = types.nullOr (types.enum [ "json" "text" ]);
      default = null;
      description = "Sets the log format. Permitted formats: 'json' (gated by LoggingBetaOptions), 'text'. (default 'text')";
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

    kubeconfig = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to kubeconfig file with authorization and master location information (the master location can be overridden by the master flag).";
    };

    master = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The address of the Kubernetes API server (overrides any value in kubeconfig).";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.kube-controller-manager = {
      description = "The Kubernetes controller manager is a daemon that embeds the core control loops shipped with Kubernetes. In applications of robotics and automation, a control loop is a non-terminating loop that regulates the state of the system. In Kubernetes, a controller is a control loop that watches the shared state of the cluster through the apiserver and makes changes attempting to move the current state towards the desired state. Examples of controllers that ship with Kubernetes today are the replication controller, endpoints controller, namespace controller, and serviceaccounts controller.";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = ''
          ${pkgs.coreutils}/bin/echo ${pkgs.kubernetes}/bin/kube-controller-manager \
              ${optionalString (cfg.contention-profiling != null) "--contention-profiling"} \
            ${optionalString (cfg.profiling != null) "--profiling ${boolToString cfg.profiling}"} \
            ${optionalString (cfg.enable-leader-migration != null) "--enable-leader-migration"} \
            ${optionalString (cfg.leader-migration-config != null) "--leader-migration-config ${cfg.leader-migration-config}"} \
            ${optionalString (cfg.allocate-node-cidrs != null) "--allocate-node-cidrs ${boolToString cfg.allocate-node-cidrs}"} \
            ${optionalString (cfg.cidr-allocator-type != null) "--cidr-allocator-type ${toString cfg.cidr-allocator-type}"} \
            ${optionalString (cfg.cloud-config != null) "--cloud-config ${cfg.cloud-config}"} \
            ${optionalString (cfg.cloud-provider != null) "--cloud-provider ${cfg.cloud-provider}"} \
            ${optionalString (cfg.cluster-cidr != null) "--cluster-cidr ${cfg.cluster-cidr}"} \
            ${optionalString (cfg.cluster-name != null) "--cluster-name ${toString cfg.cluster-name}"} \
            ${optionalString (cfg.configure-cloud-routes != null) "--configure-cloud-routes ${boolToString cfg.configure-cloud-routes}"} \
            ${optionalString (cfg.controller-start-interval != null) "--controller-start-interval ${cfg.controller-start-interval}"} \
            ${optionalString (cfg.controllers != null) "--controllers \"${concatStringsSep "," cfg.controllers}\""} \
            ${optionalString (cfg.external-cloud-volume-plugin != null) "--external-cloud-volume-plugin ${cfg.external-cloud-volume-plugin}"} \
            ${optionalString (cfg.feature-gates != null) "--feature-gates \"${concatStringsSep "," cfg.feature-gates}\""} \
            ${optionalString (cfg.kube-api-burst != null) "--kube-api-burst ${toString cfg.kube-api-burst}"} \
            ${optionalString (cfg.kube-api-content-type != null) "--kube-api-content-type ${cfg.kube-api-content-type}"} \
            ${optionalString (cfg.kube-api-qps != null) "--kube-api-qps ${toString cfg.kube-api-qps}"} \
            ${optionalString (cfg.leader-elect != null) "--leader-elect ${boolToString cfg.leader-elect}"} \
            ${optionalString (cfg.leader-elect-lease-duration != null) "--leader-elect-lease-duration ${cfg.leader-elect-lease-duration}"} \
            ${optionalString (cfg.leader-elect-renew-deadline != null) "--leader-elect-renew-deadline ${cfg.leader-elect-renew-deadline}"} \
            ${optionalString (cfg.leader-elect-resource-lock != null) "--leader-elect-resource-lock ${toString cfg.leader-elect-resource-lock}"} \
            ${optionalString (cfg.leader-elect-resource-name != null) "--leader-elect-resource-name ${cfg.leader-elect-resource-name}"} \
            ${optionalString (cfg.leader-elect-resource-namespace != null) "--leader-elect-resource-namespace ${cfg.leader-elect-resource-namespace}"} \
            ${optionalString (cfg.leader-elect-retry-period != null) "--leader-elect-retry-period ${cfg.leader-elect-retry-period}"} \
            ${optionalString (cfg.min-resync-period != null) "--min-resync-period ${cfg.min-resync-period}"} \
            ${optionalString (cfg.node-monitor-period != null) "--node-monitor-period ${cfg.node-monitor-period}"} \
            ${optionalString (cfg.route-reconciliation-period != null) "--route-reconciliation-period ${cfg.route-reconciliation-period}"} \
            ${optionalString (cfg.use-service-account-credentials != null) "--use-service-account-credentials ${boolToString cfg.use-service-account-credentials}"} \
            ${optionalString (cfg.concurrent-service-syncs != null) "--concurrent-service-syncs ${toString cfg.concurrent-service-syncs}"} \
            ${optionalString (cfg.bind-address != null) "--bind-address ${cfg.bind-address}"} \
            ${optionalString (cfg.cert-dir != null) "--cert-dir ${toString cfg.cert-dir}"} \
            ${optionalString (cfg.http2-max-streams-per-connection != null) "--http2-max-streams-per-connection ${toString cfg.http2-max-streams-per-connection}"} \
            ${optionalString (cfg.permit-address-sharing != null) "--permit-address-sharing ${boolToString cfg.permit-address-sharing}"} \
            ${optionalString (cfg.permit-port-sharing != null) "--permit-port-sharing ${boolToString cfg.permit-port-sharing}"} \
            ${optionalString (cfg.secure-port != null) "--secure-port ${toString cfg.secure-port}"} \
            ${optionalString (cfg.tls-cert-file != null) "--tls-cert-file ${toString cfg.tls-cert-file}"} \
            ${optionalString (cfg.cert-dir != null) "--cert-dir ${toString cfg.cert-dir}"} \
            ${optionalString (cfg.tls-cipher-suites != null) "--tls-cipher-suites \"${concatStringsSep "," cfg.tls-cipher-suites}\""} \
            ${optionalString (cfg.tls-min-version != null) "--tls-min-version ${toString cfg.tls-min-version}"} \
            ${optionalString (cfg.tls-private-key-file != null) "--tls-private-key-file ${toString cfg.tls-private-key-file}"} \
            ${optionalString (cfg.tls-sni-cert-key != null) "--tls-sni-cert-key \"${concatStringsSep "," cfg.tls-sni-cert-key}\""} \
            ${optionalString (cfg.authentication-kubeconfig != null) "--authentication-kubeconfig ${toString cfg.authentication-kubeconfig}"} \
            ${optionalString (cfg.authentication-skip-lookup != null) "--authentication-skip-lookup ${boolToString cfg.authentication-skip-lookup}"} \
            ${optionalString (cfg.authentication-token-webhook-cache-ttl != null) "--authentication-token-webhook-cache-ttl ${toString cfg.authentication-token-webhook-cache-ttl}"} \
            ${optionalString (cfg.authentication-tolerate-lookup-failure != null) "--authentication-tolerate-lookup-failure ${boolToString cfg.authentication-tolerate-lookup-failure}"} \
            ${optionalString (cfg.authentication-tolerate-lookup-failure != null) "--authentication-tolerate-lookup-failure ${toString cfg.authentication-tolerate-lookup-failure}"} \
            ${optionalString (cfg.client-ca-file != null) "--client-ca-file ${toString cfg.client-ca-file}"} \
            ${optionalString (cfg.requestheader-allowed-names != null) "--requestheader-allowed-names \"${concatStringsSep "," cfg.requestheader-allowed-names}\""} \
            ${optionalString (cfg.requestheader-client-ca-file != null) "--requestheader-client-ca-file ${toString cfg.requestheader-client-ca-file}"} \
              ${optionalString (cfg.requestheader-extra-headers-prefix != null) "--requestheader-extra--headers-prefix \"${concatStringsSep ","  cfg.requestheader-extra-headers-prefix}\""} \
            ${optionalString (cfg.requestheader-group-headers != null) "--requestheader-group-headers \"${concatStringsSep ","  cfg.requestheader-group-headers}\""} \
            ${optionalString (cfg.requestheader-username-headers != null) "--requestheader-username-headers \"${concatStringsSep ","  cfg.requestheader-username-headers}\""} \
            ${optionalString (cfg.requestheader-client-ca-file != null) "--requestheader-client-ca-file ${toString cfg.requestheader-client-ca-file}"} \
            ${optionalString (cfg.requestheader-username-headers != null) "--requestheader-username-headers ${toString cfg.requestheader-username-headers}"} \
            ${optionalString (cfg.requestheader-extra-headers-prefix != null) "--requestheader-extra-headers-prefix ${toString cfg.requestheader-extra-headers-prefix}"} \
            ${optionalString (cfg.requestheader-group-headers != null) "--requestheader-group-headers ${toString cfg.requestheader-group-headers}"} \
            ${optionalString (cfg.authorization-always-allow-paths != null) "--authorization-always-allow-paths \"${concatStringsSep "," cfg.authorization-always-allow-paths}\""} \
            ${optionalString (cfg.authorization-kubeconfig != null) "--authorization-kubeconfig ${toString cfg.authorization-kubeconfig}"} \
            ${optionalString (cfg.authorization-webhook-cache-authorized-ttl != null) "--authorization-webhook-cache-authorized-ttl ${toString cfg.authorization-webhook-cache-authorized-ttl}"} \
            ${optionalString (cfg.authorization-webhook-cache-unauthorized-ttl != null) "--authorization-webhook-cache-unauthorized-ttl ${toString cfg.authorization-webhook-cache-unauthorized-ttl}"} \
            ${optionalString (cfg.attach-detach-reconcile-sync-period != null) "--attach-detach-reconcile-sync-period ${toString cfg.attach-detach-reconcile-sync-period}"} \
            ${optionalString (cfg.disable-attach-detach-reconcile-sync != null) "--disable-attach-detach-reconcile-sync"} \
            ${optionalString (cfg.cluster-signing-cert-file != null) "--cluster-signing-cert-file ${toString cfg.cluster-signing-cert-file}"} \
            ${optionalString (cfg.cluster-signing-duration != null) "--cluster-signing-duration ${toString cfg.cluster-signing-duration}"} \
            ${optionalString (cfg.cluster-signing-key-file != null) "--cluster-signing-key-file ${toString cfg.cluster-signing-key-file}"} \
            ${optionalString (cfg.cluster-signing-kube-apiserver-client-cert-file != null) "--cluster-signing-kube-apiserver-client-cert-file ${toString cfg.cluster-signing-kube-apiserver-client-cert-file}"} \
            ${optionalString (cfg.cluster-signing-kube-apiserver-client-key-file != null) "--cluster-signing-kube-apiserver-client-key-file ${toString cfg.cluster-signing-kube-apiserver-client-key-file}"} \
            ${optionalString (cfg.cluster-signing-kubelet-client-cert-file != null) "--cluster-signing-kubelet-client-cert-file ${toString cfg.cluster-signing-kubelet-client-cert-file}"} \
            ${optionalString (cfg.cluster-signing-kubelet-client-key-file != null) "--cluster-signing-kubelet-client-key-file ${toString cfg.cluster-signing-kubelet-client-key-file}"} \
            ${optionalString (cfg.cluster-signing-kubelet-serving-cert-file != null) "--cluster-signing-kubelet-serving-cert-file ${toString cfg.cluster-signing-kubelet-serving-cert-file}"} \
            ${optionalString (cfg.cluster-signing-kubelet-serving-key-file != null) "--cluster-signing-kubelet-serving-key-file ${toString cfg.cluster-signing-kubelet-serving-key-file}"} \
            ${optionalString (cfg.cluster-signing-legacy-unknown-cert-file != null) "--cluster-signing-legacy-unknown-cert-file ${toString cfg.cluster-signing-legacy-unknown-cert-file}"} \
            ${optionalString (cfg.cluster-signing-legacy-unknown-key-file != null) "--cluster-signing-legacy-unknown-key-file ${toString cfg.cluster-signing-legacy-unknown-key-file}"} \
            ${optionalString (cfg.concurrent-deployment-syncs != null) "--concurrent-deployment-syncs ${toString cfg.concurrent-deployment-syncs}"} \
            ${optionalString (cfg.concurrent-statefulset-syncs != null) "--concurrent-statefulset-syncs ${toString cfg.concurrent-statefulset-syncs}"} \
            ${optionalString (cfg.concurrent-endpoint-syncs != null) "--concurrent-endpoint-syncs ${toString cfg.concurrent-endpoint-syncs}"} \
            ${optionalString (cfg.endpoint-updates-batch-period != null) "--endpoint-updates-batch-period ${toString cfg.endpoint-updates-batch-period}"} \
            ${optionalString (cfg.concurrent-service-endpoint-syncs != null) "--concurrent-service-endpoint-syncs ${toString cfg.concurrent-service-endpoint-syncs}"} \
            ${optionalString (cfg.endpointslice-updates-batch-period != null) "--endpointslice-updates-batch-period ${toString cfg.endpointslice-updates-batch-period}"} \
            ${optionalString (cfg.max-endpoints-per-slice != null) "--max-endpoints-per-slice ${toString cfg.max-endpoints-per-slice}"} \
            ${optionalString (cfg.mirroring-concurrent-service-endpoint-syncs != null) "--mirroring-concurrent-service-endpoint-syncs ${toString cfg.mirroring-concurrent-service-endpoint-syncs}"} \
            ${optionalString (cfg.mirroring-endpointslice-updates-batch-period != null) "--mirroring-endpointslice-updates-batch-period ${toString cfg.mirroring-endpointslice-updates-batch-period}"} \
            ${optionalString (cfg.mirroring-max-endpoints-per-subset != null) "--mirroring-max-endpoints-per-subset ${toString cfg.mirroring-max-endpoints-per-subset}"} \
            ${optionalString (cfg.concurrent-ephemeralvolume-syncs != null) "--concurrent-ephemeralvolume-syncs ${toString cfg.concurrent-ephemeralvolume-syncs}"} \
            ${optionalString (cfg.concurrent-gc-syncs != null) "--concurrent-gc-syncs ${toString cfg.concurrent-gc-syncs}"} \
            ${optionalString (cfg.enable-garbage-collector != null) "--enable-garbage-collector ${boolToString cfg.enable-garbage-collector}"} \
            ${optionalString (cfg.concurrent-horizontal-pod-autoscaler-syncs != null) "--concurrent-horizontal-pod-autoscaler-syncs ${toString cfg.concurrent-horizontal-pod-autoscaler-syncs}"} \
            ${optionalString (cfg.horizontal-pod-autoscaler-cpu-initialization-period != null) "--horizontal-pod-autoscaler-cpu-initialization-period ${toString cfg.horizontal-pod-autoscaler-cpu-initialization-period}"} \
            ${optionalString (cfg.horizontal-pod-autoscaler-downscale-stabilization != null) "--horizontal-pod-autoscaler-downscale-stabilization ${toString cfg.horizontal-pod-autoscaler-downscale-stabilization}"} \
            ${optionalString (cfg.horizontal-pod-autoscaler-initial-readiness-delay != null) "--horizontal-pod-autoscaler-initial-readiness-delay ${toString cfg.horizontal-pod-autoscaler-initial-readiness-delay}"} \
            ${optionalString (cfg.horizontal-pod-autoscaler-sync-period != null) "--horizontal-pod-autoscaler-sync-period ${toString cfg.horizontal-pod-autoscaler-sync-period}"} \
            ${optionalString (cfg.horizontal-pod-autoscaler-tolerance != null) "--horizontal-pod-autoscaler-tolerance ${toString cfg.horizontal-pod-autoscaler-tolerance}"} \
            ${optionalString (cfg.concurrent-job-syncs != null) "--concurrent-job-syncs ${toString cfg.concurrent-job-syncs}"} \
            ${optionalString (cfg.concurrent-cron-job-syncs != null) "--concurrent-cron-job-syncs ${toString cfg.concurrent-cron-job-syncs}"} \
            ${optionalString (cfg.legacy-service-account-token-clean-up-period != null) "--legacy-service-account-token-clean-up-period ${toString cfg.legacy-service-account-token-clean-up-period}"} \
            ${optionalString (cfg.concurrent-namespace-syncs != null) "--concurrent-namespace-syncs ${toString cfg.concurrent-namespace-syncs}"} \
            ${optionalString (cfg.namespace-sync-period != null) "--namespace-sync-period ${toString cfg.namespace-sync-period}"} \
            ${optionalString (cfg.node-cidr-mask-size != null) "--node-cidr-mask-size ${toString cfg.node-cidr-mask-size}"} \
            ${optionalString (cfg.node-cidr-mask-size-ipv4 != null) "--node-cidr-mask-size-ipv4 ${toString cfg.node-cidr-mask-size-ipv4}"} \
            ${optionalString (cfg.node-cidr-mask-size-ipv6 != null) "--node-cidr-mask-size-ipv6 ${toString cfg.node-cidr-mask-size-ipv6}"} \
            ${optionalString (cfg.service-cluster-ip-range != null) "--service-cluster-ip-range ${toString cfg.service-cluster-ip-range}"} \
            ${optionalString (cfg.large-cluster-size-threshold != null) "--large-cluster-size-threshold ${toString cfg.large-cluster-size-threshold}"} \
            ${optionalString (cfg.node-eviction-rate != null) "--node-eviction-rate ${toString cfg.node-eviction-rate}"} \
            ${optionalString (cfg.node-monitor-grace-period != null) "--node-monitor-grace-period ${toString cfg.node-monitor-grace-period}"} \
            ${optionalString (cfg.node-startup-grace-period != null) "--node-startup-grace-period ${toString cfg.node-startup-grace-period}"} \
            ${optionalString (cfg.secondary-node-eviction-rate != null) "--secondary-node-eviction-rate ${toString cfg.secondary-node-eviction-rate}"} \
            ${optionalString (cfg.unhealthy-zone-threshold != null) "--unhealthy-zone-threshold ${toString cfg.unhealthy-zone-threshold}"} \
            ${optionalString (cfg.enable-dynamic-provisioning != null) "--enable-dynamic-provisioning ${boolToString cfg.enable-dynamic-provisioning}"} \
            ${optionalString (cfg.enable-hostpath-provisioner != null) "--enable-hostpath-provisioner"} \
            ${optionalString (cfg.flex-volume-plugin-dir != null) "--flex-volume-plugin-dir ${toString cfg.flex-volume-plugin-dir}"} \
            ${optionalString (cfg.pv-recycler-increment-timeout-nfs != null) "--pv-recycler-increment-timeout-nfs ${toString cfg.pv-recycler-increment-timeout-nfs}"} \
            ${optionalString (cfg.pv-recycler-minimum-timeout-hostpath != null) "--pv-recycler-minimum-timeout-hostpath ${toString cfg.pv-recycler-minimum-timeout-hostpath}"} \
            ${optionalString (cfg.pv-recycler-minimum-timeout-nfs != null) "--pv-recycler-minimum-timeout-nfs ${toString cfg.pv-recycler-minimum-timeout-nfs}"} \
            ${optionalString (cfg.pv-recycler-pod-template-filepath-hostpath != null) "--pv-recycler-pod-template-filepath-hostpath ${toString cfg.pv-recycler-pod-template-filepath-hostpath}"} \
            ${optionalString (cfg.pv-recycler-pod-template-filepath-nfs != null) "--pv-recycler-pod-template-filepath-nfs ${toString cfg.pv-recycler-pod-template-filepath-nfs}"} \
            ${optionalString (cfg.pv-recycler-timeout-increment-hostpath != null) "--pv-recycler-timeout-increment-hostpath ${toString cfg.pv-recycler-timeout-increment-hostpath}"} \
            ${optionalString (cfg.pvclaimbinder-sync-period != null) "--pvclaimbinder-sync-period ${toString cfg.pvclaimbinder-sync-period}"} \
            ${optionalString (cfg.terminated-pod-gc-threshold != null) "--terminated-pod-gc-threshold ${toString cfg.terminated-pod-gc-threshold}"} \
            ${optionalString (cfg.concurrent-replicaset-syncs != null) "--concurrent-replicaset-syncs ${toString cfg.concurrent-replicaset-syncs}"} \
            ${optionalString (cfg.concurrent-rc-syncs != null) "--concurrent-rc-syncs ${toString cfg.concurrent-rc-syncs}"} \
            ${optionalString (cfg.concurrent-resource-quota-syncs != null) "--concurrent-resource-quota-syncs ${toString cfg.concurrent-resource-quota-syncs}"} \
            ${optionalString (cfg.resource-quota-sync-period != null) "--resource-quota-sync-period ${toString cfg.resource-quota-sync-period}"} \
            ${optionalString (cfg.concurrent-serviceaccount-token-syncs != null) "--concurrent-serviceaccount-token-syncs ${toString cfg.concurrent-serviceaccount-token-syncs}"} \
            ${optionalString (cfg.root-ca-file != null) "--root-ca-file ${toString cfg.root-ca-file}"} \
            ${optionalString (cfg.service-account-private-key-file != null) "--service-account-private-key-file ${toString cfg.service-account-private-key-file}"} \
            ${optionalString (cfg.concurrent-ttl-after-finished-syncs != null) "--concurrent-ttl-after-finished-syncs ${toString cfg.concurrent-ttl-after-finished-syncs}"} \
            ${optionalString (cfg.concurrent-validating-admission-policy-status-syncs != null) "--concurrent-validating-admission-policy-status-syncs ${toString cfg.concurrent-validating-admission-policy-status-syncs}"} \
            ${optionalString (cfg.allow-metric-labels != null) "--allow-metric-labels \"${concatStringsSep "," cfg.allow-metric-labels}\""} \
            ${optionalString (cfg.disabled-metrics != null) "--disabled-metrics \"${concatStringsSep "," cfg.disabled-metrics}\""} \
            ${optionalString (cfg.show-hidden-metrics-for-version != null) "--show-hidden-metrics-for-version ${toString cfg.show-hidden-metrics-for-version}"} \
            ${optionalString (cfg.log-flush-frequency != null) "--log-flush-frequency ${toString cfg.log-flush-frequency}"} \
            ${optionalString (cfg.log-json-info-buffer-size != null) "--log-json-info-buffer-size ${toString cfg.log-json-info-buffer-size}"} \
            ${optionalString (cfg.log-json-split-stream != null) "--log-json-split-stream"} \
            ${optionalString (cfg.logging-format != null) "--logging-format ${toString cfg.logging-format}"} \
            ${optionalString (cfg.v != null) "--v ${toString cfg.v}"} \
            ${optionalString (cfg.vmodule != null) "--vmodule \"${concatStringsSep "," cfg.vmodule}\""} \
            ${optionalString (cfg.kubeconfig != null) "--kubeconfig ${toString cfg.kubeconfig}"} \
            ${optionalString (cfg.master != null) "--master ${toString cfg.master}"}
        '';
      };
    };
  };
}
