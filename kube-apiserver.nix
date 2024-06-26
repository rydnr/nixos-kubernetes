{
  config,
  pkgs,
  lib,
  ...
}:

with lib;

let
  cfg = config.services.raw-kube-apiserver;
  boolToString = b: if b then "true" else "false";
  oidc-required-claim-items = if cfg.oidc-required-claim != null then map (item: "--oidc-required-claim ${item}") cfg.oidc-required-claim else [];
  description = "The Kubernetes API server validates and configures data for the api objects which include pods, services, replicationcontrollers, and others. The API Server services REST operations and provides the frontend to the cluster's shared state through which all other components interact.";
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
  options.services.raw-kube-apiserver = {
    enable = mkOption {
      type = types.bool;
      default = false;
      inherit description;
    };

    # Generic flags
    advertise-address = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address on which to advertise the apiserver to members of the cluster. This address must be reachable by the rest of the cluster. If blank, the --bind-address will be used. If --bind-address is unspecified, the host's default interface will be used.";
    };
    cloud-provider-gce-l7lb-src-cidrs = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "CIDRs opened in GCE firewall for L7 LB traffic proxy & health checks (default 130.211.0.0/22,35.191.0.0/16)";
    };
    cors-allowed-origins = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of allowed origins for CORS, comma separated. An allowed origin can be a regular expression to support subdomain matching. If this list is empty CORS will not be enabled. Please ensure each expression matches the entire hostname by anchoring to the start with '^' or including the '//' prefix, and by anchoring to the end with '$' or including the ':' port separator suffix. Examples of valid expressions are '//example\.com(:|$)' and '^https://example\.com(:|$)'";
    };
    default-not-ready-toleration-seconds = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Indicates the tolerationSeconds of the toleration for notReady:NoExecute that is added by default to every pod that does not already have such a toleration. (default 300)";
    };
    default-unreachable-toleration-seconds = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Indicates the tolerationSeconds of the toleration for unreachable:NoExecute that is added by default to every pod that does not already have such a toleration. (default 300)";
    };
    enable-priority-and-fairness = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true and the APIPriorityAndFairness feature gate is enabled, replace the max-in-flight handler with an enhanced one that queues and dispatches with priority and fairness (default true)";
    };
    external-hostname = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The hostname to use when generating externalized URLs for this master (e.g. Swagger API Docs or OpenID Discovery).";
    };
    feature-gates = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = featureGatesDescription;
    };
    goaway-chance = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "To prevent HTTP/2 clients from getting stuck on a single apiserver, randomly close a connection (GOAWAY). The client's other in-flight requests won't be affected, and the client will reconnect, likely landing on a different apiserver after going through the load balancer again. This argument sets the fraction of requests that will be sent a GOAWAY. Clusters with single apiservers, or which don't use a load balancer, should NOT enable this. Min is 0 (off), Max is .02 (1/50 requests); .001 (1/1000) is a recommended starting point.";
    };
    livez-grace-period = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "This option represents the maximum amount of time it should take for apiserver to complete its startup sequence and become live. From apiserver's start time to when this amount of time has elapsed, /livez will assume that unfinished post-start hooks will complete successfully and therefore return true.";
    };
    max-mutating-requests-inflight = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "This and --max-requests-inflight are summed to determine the server's total concurrency limit (which must be positive) if --enable-priority-and-fairness is true. Otherwise, this flag limits the maximum number of mutating requests in flight, or a zero value disables the limit completely. (default 200)";
    };
    max-requests-inflight = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "This and --max-mutating-requests-inflight are summed to determine the server's total concurrency limit (which must be positive) if --enable-priority-and-fairness is true. Otherwise, this flag limits the maximum number of non-mutating requests in flight, or a zero value disables the limit completely. (default 400)";
    };
    min-request-timeout = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "An optional field indicating the minimum number of seconds a handler must keep a request open before timing it out. Currently only honored by the watch request handler, which picks a randomized value above this number as the connection timeout, to spread out load. (default 1800)";
    };
    request-timeout = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "An optional field indicating the duration a handler must keep a request open before timing it out. This is the default request timeout for requests but may be overridden by flags such as --min-request-timeout for specific types of requests. (default 1m0s)";
    };
    shutdown-delay-duration = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Time to delay the termination. During that time the server keeps serving requests normally. The endpoints /healthz and /livez will return success, but /readyz immediately returns failure. Graceful termination starts after this delay has elapsed. This can be used to allow load balancer to stop sending traffic to this server.";
    };
    shutdown-send-retry-after = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true the HTTP Server will continue listening until all non long running request(s) in flight have been drained, during this window all incoming requests will be rejected with a status code 429 and a 'Retry-After' response header, in addition 'Connection: close' response header is set in order to tear down the TCP connection when idle.";
    };
    shutdown-watch-termination-grace-period = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "This option, if set, represents the maximum amount of grace period the apiserver will wait for active watch request(s) to drain during the graceful server shutdown window.";
    };
    strict-transport-security-directives = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of directives for HSTS, comma separated. If this list is empty, then HSTS directives will not be added. Example: ['max-age=31536000' 'includeSubDomains' 'preload']";
    };

    # Etcd flags
    delete-collection-workers = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Number of workers spawned for DeleteCollection call. These are used to speed up namespace cleanup. (default 1)";
    };
    enable-garbage-collector = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enables the generic garbage collector. MUST be synced with the corresponding flag of the kube-controller-manager. (default true)";
    };
    encryption-provider-config = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The file containing configuration for encryption providers to be used for storing secrets in etcd";
    };
    encryption-provider-config-automatic-reload = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Determines if the file set by --encryption-provider-config should be automatically reloaded if the disk contents change. Setting this to true disables the ability to uniquely identify distinct KMS plugins via the API server healthz endpoints.";
    };
    etcd-cafile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "SSL Certificate Authority file used to secure etcd communication.";
    };
    etcd-certfile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "SSL certification file used to secure etcd communication.";
    };
    etcd-compaction-interval = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The interval of compaction requests. If 0, the compaction request from apiserver is disabled. (default 5m0s)";
    };
    etcd-count-metric-poll-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Frequency of polling etcd for number of resources per type. 0 disables the metric collection. (default 1m0s)";
    };
    etcd-db-metric-poll-interval = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The interval of requests to poll etcd and update metric. 0 disables the metric collection (default 30s)";
    };
    etcd-healthcheck-timeout = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The timeout to use when checking etcd health. (default 2s)";
    };
    etcd-keyfile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "SSL key file used to secure etcd communication.";
    };
    etcd-prefix = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The prefix to prepend to all resource paths in etcd. (default " /registry ")";
    };
    etcd-readycheck-timeout = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The timeout to use when checking etcd readiness (default 2s)";
    };
    etcd-servers = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of etcd servers to connect with (scheme://ip:port), comma separated.";
    };
    etcd-servers-overrides = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Per-resource etcd servers overrides, comma separated. The individual override format: group/resource#servers, where servers are URLs, semicolon separated. Note that this applies only to resources compiled into this server binary. ";
    };
    lease-reuse-duration-seconds = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The time in seconds that each lease is reused. A lower value could avoid large number of objects reusing the same lease. Notice that a too small value may cause performance problems at storage layer. (default 60)";
    };
    storage-backend = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The storage backend for persistence. Options: 'etcd3' (default).";
    };
    storage-media-type = mkOption {
      type = types.nullOr (types.enum [
        "application/json"
        "application/yaml"
        "application/vnd.kubernetes.protobuf"
      ]);
      default = null;
      description = "The media type to use to store objects in storage. Some resources or storage backends may only support a specific media type and will ignore this setting. Supported media types: [application/json, application/yaml, application/vnd.kubernetes.protobuf] (default 'application/vnd.kubernetes.protobuf ')";
    };
    watch-cache = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable watch caching in the apiserver (default true)";
    };
    watch-cache-sizes = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Watch cache size settings for some resources (pods, nodes, etc.), comma separated. The individual setting format: resource[.group]#size, where resource is lowercase plural (no version), group is omitted for resources of apiVersion v1 (the legacy core API) and included for others, and size is a number. This option is only meaningful for resources built into the apiserver, not ones defined by CRDs or aggregated from external servers, and is only consulted if the watch-cache is enabled. The only meaningful size setting to supply here is zero, which means to disable watch caching for the associated resource; all non-zero values are equivalent and mean to not disable watch caching for that resource";
    };
    # Secure serving flags
    bind-address = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address on which to listen for the --secure-port port. The associated interface(s) must be reachable by the rest of the cluster, and by CLI/web clients. If blank or an unspecified address (0.0.0.0 or ::), all interfaces and IP address families will be used. (default 0.0.0.0)";
    };
    cert-dir = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The directory where the TLS certs are located. If --tls-cert-file and --tls-private-key-file are provided, this flag will be ignored. (default /var/run/kubernetes)";
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
      description = "The port on which to serve HTTPS with authentication and authorization. It cannot be switched off with 0. (default 6443)";
    };
    tls-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert). If HTTPS serving is enabled, and --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to the directory specified by --cert-dir.";
    };
    tls-cipher-suites = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "" "
Comma-separated list of cipher suites for the server. If omitted, the default Go cipher suites will be used. Preferred values:
Preferred values: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.
Insecure values: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_RC4_128_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_RC4_128_SHA.
" "";
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

    # audit flags
    audit-log-batch-buffer-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The size of the buffer to store events before batching and writing. Only used in batch mode. (default 10000)";
    };
    audit-log-batch-max-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The maximum size of a batch. Only used in batch mode. (default 1)";
    };
    audit-log-batch-max-wait = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The amount of time to wait before force writing the batch that hadn't reached the max size. Only used in batch mode.";
    };
    audit-log-batch-throttle-burst = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum number of requests sent at the same moment if ThrottleQPS was not utilized before. Only used in batch mode.";
    };
    audit-log-batch-throttle-enable = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Whether batching throttling is enabled. Only used in batch mode.";
    };
    audit-log-batch-throttle-qps = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "Maximum average number of batches per second. Only used in batch mode.";
    };
    audit-log-compress = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If set, the rotated log files will be compressed using gzip.";
    };
    audit-log-format = mkOption {
      type = types.nullOr (types.enum [ "legacy" "json" ]);
      default = null;
      description = "Format of saved audits. 'legacy' indicates 1-line text format for each event. 'json' indicates structured json format. Known formats are legacy,json. (default 'json')";
    };
    audit-log-maxage = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The maximum number of days to retain old audit log files based on the timestamp encoded in their filename.";
    };
    audit-log-maxbackup = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The maximum number of old audit log files to retain. Setting a value of 0 will mean there's no restriction on the number of files.";
    };
    audit-log-maxsize = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The maximum size in megabytes of the audit log file before it gets rotated.";
    };
    audit-log-mode = mkOption {
      type = types.nullOr (types.enum [ "batch" "blocking" "blocking-strict" ]);
      default = null;
      description = "Strategy for sending audit events. Blocking indicates sending events should block server responses. Batch causes the backend to buffer and write events asynchronously. Known modes are batch,blocking,blocking-strict. (default 'blocking')";
    };
    audit-log-path = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "If set, all requests coming to the apiserver will be logged to this file.  '-' means standard out.";
    };
    audit-log-truncate-enabled = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Whether event and batch truncating is enabled.";
    };
    audit-log-truncate-max-batch-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum size of the batch sent to the underlying backend. Actual serialized size can be several hundreds of bytes greater. If a batch exceeds this limit, it is split into several batches of smaller size. (default 10485760)";
    };
    audit-log-truncate-max-event-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum size of the audit event sent to the underlying backend. If the size of an event is greater than this number, first request and response are removed, and if this doesn't reduce the size enough, event is discarded. (default 102400)";
    };
    audit-log-version = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "API group and version used for serializing audit events written to log. (default 'udit.k8s.io/v1')";
    };
    audit-policy-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the file that defines the audit policy configuration.";
    };
    audit-webhook-batch-buffer-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The size of the buffer to store events before batching and writing. Only used in batch mode. (default 10000)";
    };
    audit-webhook-batch-max-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The maximum size of a batch. Only used in batch mode. (default 400)";
    };
    audit-webhook-batch-max-wait = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The amount of time to wait before force writing the batch that hadn't reached the max size. Only used in batch mode. (default 30s)";
    };
    audit-webhook-batch-throttle-burst = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum number of requests sent at the same moment if ThrottleQPS was not utilized before. Only used in batch mode. (default 15)";
    };
    audit-webhook-batch-throttle-enable = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Whether batching throttling is enabled. Only used in batch mode. (default true)";
    };
    audit-webhook-batch-throttle-qps = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "Maximum average number of batches per second. Only used in batch mode. (default 10)";
    };
    audit-webhook-config-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a kubeconfig formatted file that defines the audit webhook configuration.";
    };
    audit-webhook-initial-backoff = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The amount of time to wait before retrying the first failed request. (default 10s)";
    };
    audit-webhook-mode = mkOption {
      type = types.nullOr (types.enum [
        "batch"
        "blocking"
        "blocking-strict"
      ]);
      default = null;
      description = "Strategy for sending audit events. Blocking indicates sending events should block server responses. Batch causes the backend to buffer and write events asynchronously. Known modes are batch,blocking,blocking-strict. (default 'batch')";
    };
    audit-webhook-truncate-enabled = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Whether event and batch truncating is enabled.";
    };
    audit-webhook-truncate-max-batch-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum size of the batch sent to the underlying backend. Actual serialized size can be several hundreds of bytes greater. If a batch exceeds this limit, it is split into several batches of smaller size. (default 10485760)";
    };
    audit-webhook-truncate-max-event-size = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum size of the audit event sent to the underlying backend. If the size of an event is greater than this number, first request and response are removed, and if this doesn't reduce the size enough, event is discarded. (default 102400)";
    };
    audit-webhook-version = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "API group and version used for serializing audit events written to webhook. (default " audit.k8s.io/v1 ")";
    };

    # features flags
    contention-profiling = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable block profiling, if profiling is enabled";
    };
    debug-socket-path = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Use an unprotected (no authn/authz) unix-domain socket for profiling with the given path";
    };
    profiling = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable profiling via web interface host:port/debug/pprof/ (default true)";
    };

    # Authentication flags
    anonymous-auth = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enables anonymous requests to the secure port of the API server. Requests that are not rejected by another authentication method are treated as anonymous requests. Anonymous requests have a username of system:anonymous, and a group name of system:unauthenticated. (default true)";
    };
    api-audiences = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "Identifiers of the API. The service account token authenticator will validate that tokens used against the API are bound to at least one of these audiences. If the --service-account-issuer flag is configured and this flag is not, this field defaults to a single element list containing the issuer URL.";
    };
    authentication-config = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File with Authentication Configuration to configure the JWT Token authenticator. Note: This feature is in Alpha since v1.29.--feature-gate=StructuredAuthenticationConfiguration=true needs to be set for enabling this feature.This feature is mutually exclusive with the oidc-* flags.";
    };
    authentication-token-webhook-cache-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache responses from the webhook token authenticator. (default 2m0s)";
    };
    authentication-token-webhook-config-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File with webhook configuration for token authentication in kubeconfig format. The API server will query the remote service to determine authentication for bearer tokens.";
    };
    authentication-token-webhook-version = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The API version of the authentication.k8s.io TokenReview to send to and expect from the webhook. (default 'v1beta1')";
    };
    client-ca-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.";
    };
    enable-bootstrap-token-auth = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable to allow secrets of type 'bootstrap.kubernetes.io/token' in the 'kube-system' namespace to be used for TLS bootstrapping authentication.";
    };
    oidc-ca-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "If set, the OpenID server's certificate will be verified by one of the authorities in the oidc-ca-file, otherwise the host's root CA set will be used.";
    };
    oidc-client-id = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The client ID for the OpenID Connect client, must be set if oidc-issuer-url is set.";
    };
    oidc-groups-claim = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "If provided, the name of a custom OpenID Connect claim for specifying user groups. The claim value is expected to be a string or array of strings. This flag is experimental, please see the authentication documentation for further details.";
    };
    oidc-groups-prefix = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "If provided, all groups will be prefixed with this value to prevent conflicts with other authentication strategies.";
    };
    oidc-issuer-url = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The URL of the OpenID issuer, only HTTPS scheme will be accepted. If set, it will be used to verify the OIDC JSON Web Token (JWT).";
    };
    oidc-required-claim = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A key=value pair that describes a required claim in the ID Token. If set, the claim is verified to be present in the ID Token with a matching value. Repeat this flag to specify multiple claims.";
    };
    oidc-signing-algs = mkOption {
      type = types.nullOr (types.enum [
        "RS256"
        "RS384"
        "RS512"
        "ES256"
        "ES384"
        "ES512"
        "PS256"
        "PS384"
        "PS512"
      ]);
      default = null;
      description = "Comma-separated list of allowed JOSE asymmetric signing algorithms. JWTs with a supported 'alg' header values are: RS256, RS384, RS512, ES256, ES384, ES512, PS256, PS384, PS512. Values are defined by RFC 7518 https://tools.ietf.org/html/rfc7518#section-3.1. (default [RS256])";
    };
    oidc-username-claim = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The OpenID claim to use as the user name. Note that claims other than the default ('sub') is not guaranteed to be unique and immutable. This flag is experimental, please see the authentication documentation for further details. (default 'sub')";
    };
    oidc-username-prefix = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "If provided, all usernames will be prefixed with this value. If not provided, username claims other than 'email' are prefixed by the issuer URL to avoid clashes. To skip any prefixing, provide the value '-'.";
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
      description = "List of request header prefixes to inspect. X-Remote-Extra- is suggested.";
    };
    requestheader-group-headers = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of request headers to inspect for groups. X-Remote-Group is suggested.";
    };
    requestheader-username-headers = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "List of request headers to inspect for usernames. X-Remote-User is common.";
    };
    service-account-extend-token-expiration = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Turns on projected service account expiration extension during token generation, which helps safe transition from legacy token to bound service account token feature. If this flag is enabled, admission injected tokens would be extended up to 1 year to prevent unexpected failure during transition, ignoring value of service-account-max-token-expiration. (default true)";
    };
    service-account-issuer = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Identifier of the service account token issuer. The issuer will assert this identifier in 'iss' claim of issued tokens. This value is a string or URI. If this option is not a valid URI per the OpenID Discovery 1.0 spec, the ServiceAccountIssuerDiscovery feature will remain disabled, even if the feature gate is set to true. It is highly recommended that this value comply with the OpenID spec: https://openid.net/specs/openid-connect-discovery-1_0.html. In practice, this means that service-account-issuer must be an https URL. It is also highly recommended that this URL be capable of serving OpenID discovery documents at {service-account-issuer}/.well-known/openid-configuration. When this flag is specified multiple times, the first is used to generate tokens and all are used to determine which issuers are accepted.";
    };
    service-account-jwks-uri = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Overrides the URI for the JSON Web Key Set in the discovery doc served at /.well-known/openid-configuration. This flag is useful if the discovery docand key set are served to relying parties from a URL other than the API server's external (as auto-detected or overridden with external-hostname).";
    };
    service-account-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File containing PEM-encoded x509 RSA or ECDSA private or public keys, used to verify ServiceAccount tokens. The specified file can contain multiple keys, and the flag can be specified multiple times with different files. If unspecified, --tls-private-key-file is used. Must be specified when --service-account-signing-key-file is provided";
    };
    service-account-lookup = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, validate ServiceAccount tokens exist in etcd as part of authentication. (default true)";
    };
    service-account-max-token-expiration = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The maximum validity duration of a token created by the service account token issuer. If an otherwise valid TokenRequest with a validity duration larger than this value is requested, a token will be issued with a validity duration of this value.";
    };
    token-auth-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "If set, the file that will be used to secure the secure port of the API server via token authentication.";
    };

    # Authorization flags
    authorization-config = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File with Authorization Configuration to configure the authorizer chain.Note: This feature is in Alpha since v1.29.--feature-gate=StructuredAuthorizationConfiguration=true feature flag needs to be set to true for enabling the functionality.This feature is mutually exclusive with the other --authorization-mode and --authorization-webhook-* flags.";
    };
    authorization-mode = mkOption {
      type = types.nullOr (types.listOf (types.enum [
        "AlwaysAllow"
        "AlwaysDeny"
        "ABAC"
        "Webhook"
        "RBAC"
        "Node"
      ]));
      default = null;
      description = "Ordered list of plug-ins to do authorization on secure port. Defaults to AlwaysAllow if --authorization-config is not used. Comma-delimited list of: AlwaysAllow,AlwaysDeny,ABAC,Webhook,RBAC,Node.";
    };
    authorization-policy-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File with authorization policy in json line by line format, used with --authorization-mode=ABAC, on the secure port.";
    };
    authorization-webhook-cache-authorized-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache 'authorized' responses from the webhook authorizer. (default 5m0s)";
    };
    authorization-webhook-cache-unauthorized-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The duration to cache 'unauthorized' responses from the webhook authorizer. (default 30s)";
    };
    authorization-webhook-config-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File with webhook configuration in kubeconfig format, used with --authorization-mode=Webhook. The API server will query the remote service to determine access on the API server's secure port.";
    };
    authorization-webhook-version = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The API version of the authorization.k8s.io SubjectAccessReview to send to and expect from the webhook. (default 'v1beta1')";
    };

    # API enablement flags:
    runtime-config = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "" "
A set of key=value pairs that enable or disable built-in APIs. Supported options are:
  v1=true|false for the core API group
  <group>/<version>=true|false for a specific API group and version (e.g. apps/v1=true)
  api/all=true|false controls all API versions
  api/ga=true|false controls all API versions of the form v[0-9]+
  api/beta=true|false controls all API versions of the form v[0-9]+beta[0-9]+
  api/alpha=true|false controls all API versions of the form v[0-9]+alpha[0-9]+
  api/legacy is deprecated, and will be removed in a future version
" "";
    };
    egress-selector-config-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File with apiserver egress selector configuration.";
    };
    admission-control = mkOption {
      type = types.nullOr (types.listOf (types.enum [
        "AlwaysAdmit"
        "AlwaysDeny"
        "AlwaysPullImages"
        "CertificateApproval"
        "CertificateSigning"
        "CertificateSubjectRestriction"
        "ClusterTrustBundleAttest"
        "DefaultIngressClass"
        "DefaultStorageClass"
        "DefaultTolerationSeconds"
        "DenyServiceExternalIPs"
        "EventRateLimit"
        "ExtendedResourceToleration"
        "ImagePolicyWebhook"
        "LimitPodHardAntiAffinityTopology"
        "LimitRanger"
        "MutatingAdmissionWebhook"
        "NamespaceAutoProvision"
        "NamespaceExists"
        "NamespaceLifecycle"
        "NodeRestriction"
        "OwnerReferencesPermissionEnforcement"
        "PersistentVolumeClaimResize"
        "PersistentVolumeLabel"
        "PodNodeSelector"
        "PodSecurity"
        "PodTolerationRestriction"
        "Priority"
        "ResourceQuota"
        "RuntimeClass"
        "ServiceAccount"
        "StorageObjectInUseProtection"
        "TaintNodesByCondition"
        "ValidatingAdmissionPolicy"
        "ValidatingAdmissionWebhook"
      ]));
      default = null;
      description = "Admission is divided into two phases. In the first phase, only mutating admission plugins run. In the second phase, only validating admission plugins run. The names in the below list may represent a validating plugin, a mutating plugin, or both. The order of plugins in which they are passed to this flag does not matter. Comma-delimited list of admission plugins: AlwaysAdmit, AlwaysDeny, AlwaysPullImages, CertificateApproval, CertificateSigning, CertificateSubjectRestriction, ClusterTrustBundleAttest, DefaultIngressClass, DefaultStorageClass, DefaultTolerationSeconds, DenyServiceExternalIPs, EventRateLimit, ExtendedResourceToleration, ImagePolicyWebhook, LimitPodHardAntiAffinityTopology, LimitRanger, MutatingAdmissionWebhook, NamespaceAutoProvision, NamespaceExists, NamespaceLifecycle, NodeRestriction, OwnerReferencesPermissionEnforcement, PersistentVolumeClaimResize, PersistentVolumeLabel, PodNodeSelector, PodSecurity, PodTolerationRestriction, Priority, ResourceQuota, RuntimeClass, ServiceAccount, StorageObjectInUseProtection, TaintNodesByCondition, ValidatingAdmissionPolicy, ValidatingAdmissionWebhook. (DEPRECATED: Use --enable-admission-plugins or --disable-admission-plugins instead. Will be removed in a future version.)";
    };
    admission-control-config-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File with admission control configuration.";
    };
    disable-admission-plugins = mkOption {
      type = types.nullOr (types.listOf (types.enum [
        "AlwaysAdmit"
        "AlwaysDeny"
        "AlwaysPullImages"
        "CertificateApproval"
        "CertificateSigning"
        "CertificateSubjectRestriction"
        "ClusterTrustBundleAttest"
        "DefaultIngressClass"
        "DefaultStorageClass"
        "DefaultTolerationSeconds"
        "DenyServiceExternalIPs"
        "EventRateLimit"
        "ExtendedResourceToleration"
        "ImagePolicyWebhook"
        "LimitPodHardAntiAffinityTopology"
        "LimitRanger"
        "MutatingAdmissionWebhook"
        "NamespaceAutoProvision"
        "NamespaceExists"
        "NamespaceLifecycle"
        "NodeRestriction"
        "OwnerReferencesPermissionEnforcement"
        "PersistentVolumeClaimResize"
        "PersistentVolumeLabel"
        "PodNodeSelector"
        "PodSecurity"
        "PodTolerationRestriction"
        "Priority"
        "ResourceQuota"
        "RuntimeClass"
        "ServiceAccount"
        "StorageObjectInUseProtection"
        "TaintNodesByCondition"
        "ValidatingAdmissionPolicy"
        "ValidatingAdmissionWebhook"
      ]));
      default = null;
      description = "The admission plugins that should be disabled although they are in the default enabled plugins list (NamespaceLifecycle, LimitRanger, ServiceAccount, TaintNodesByCondition, PodSecurity, Priority, DefaultTolerationSeconds, DefaultStorageClass, StorageObjectInUseProtection, PersistentVolumeClaimResize, RuntimeClass, CertificateApproval, CertificateSigning, ClusterTrustBundleAttest, CertificateSubjectRestriction, DefaultIngressClass, MutatingAdmissionWebhook, ValidatingAdmissionPolicy, ValidatingAdmissionWebhook, ResourceQuota). Comma-delimited list of admission plugins: AlwaysAdmit, AlwaysDeny, AlwaysPullImages, CertificateApproval, CertificateSigning, CertificateSubjectRestriction, ClusterTrustBundleAttest, DefaultIngressClass, DefaultStorageClass, DefaultTolerationSeconds, DenyServiceExternalIPs, EventRateLimit, ExtendedResourceToleration, ImagePolicyWebhook, LimitPodHardAntiAffinityTopology, LimitRanger, MutatingAdmissionWebhook, NamespaceAutoProvision, NamespaceExists, NamespaceLifecycle, NodeRestriction, OwnerReferencesPermissionEnforcement, PersistentVolumeClaimResize, PersistentVolumeLabel, PodNodeSelector, PodSecurity, PodTolerationRestriction, Priority, ResourceQuota, RuntimeClass, ServiceAccount, StorageObjectInUseProtection, TaintNodesByCondition, ValidatingAdmissionPolicy, ValidatingAdmissionWebhook. The order of plugins in this flag does not matter.";
    };
    enable-admission-plugins = mkOption {
      type = types.nullOr (types.listOf (types.enum [
        "AlwaysAdmit"
        "AlwaysDeny"
        "AlwaysPullImages"
        "CertificateApproval"
        "CertificateSigning"
        "CertificateSubjectRestriction"
        "ClusterTrustBundleAttest"
        "DefaultIngressClass"
        "DefaultStorageClass"
        "DefaultTolerationSeconds"
        "DenyServiceExternalIPs"
        "EventRateLimit"
        "ExtendedResourceToleration"
        "ImagePolicyWebhook"
        "LimitPodHardAntiAffinityTopology"
        "LimitRanger"
        "MutatingAdmissionWebhook"
        "NamespaceAutoProvision"
        "NamespaceExists"
        "NamespaceLifecycle"
        "NodeRestriction"
        "OwnerReferencesPermissionEnforcement"
        "PersistentVolumeClaimResize"
        "PersistentVolumeLabel"
        "PodNodeSelector"
        "PodSecurity"
        "PodTolerationRestriction"
        "Priority"
        "ResourceQuota"
        "RuntimeClass"
        "ServiceAccount"
        "StorageObjectInUseProtection"
        "TaintNodesByCondition"
        "ValidatingAdmissionPolicy"
        "ValidatingAdmissionWebhook"
      ]));
      default = null;
      description = "The admission plugins that should be disabled although they are in the default enabled plugins list (NamespaceLifecycle, LimitRanger, ServiceAccount, TaintNodesByCondition, PodSecurity, Priority, DefaultTolerationSeconds, DefaultStorageClass, StorageObjectInUseProtection, PersistentVolumeClaimResize, RuntimeClass, CertificateApproval, CertificateSigning, ClusterTrustBundleAttest, CertificateSubjectRestriction, DefaultIngressClass, MutatingAdmissionWebhook, ValidatingAdmissionPolicy, ValidatingAdmissionWebhook, ResourceQuota). Comma-delimited list of admission plugins: AlwaysAdmit, AlwaysDeny, AlwaysPullImages, CertificateApproval, CertificateSigning, CertificateSubjectRestriction, ClusterTrustBundleAttest, DefaultIngressClass, DefaultStorageClass, DefaultTolerationSeconds, DenyServiceExternalIPs, EventRateLimit, ExtendedResourceToleration, ImagePolicyWebhook, LimitPodHardAntiAffinityTopology, LimitRanger, MutatingAdmissionWebhook, NamespaceAutoProvision, NamespaceExists, NamespaceLifecycle, NodeRestriction, OwnerReferencesPermissionEnforcement, PersistentVolumeClaimResize, PersistentVolumeLabel, PodNodeSelector, PodSecurity, PodTolerationRestriction, Priority, ResourceQuota, RuntimeClass, ServiceAccount, StorageObjectInUseProtection, TaintNodesByCondition, ValidatingAdmissionPolicy, ValidatingAdmissionWebhook. The order of plugins in this flag does not matter.";
    };

    # Metrics flags
    allow-metric-labels = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "The map from metric-label to value allow-list of this label. The key's format is <MetricName>,<LabelName>. The value's format is <allowed_value>,<allowed_value>...e.g. metric1,label1='v1,v2,v3', metric1,label2='v1,v2,v3' metric2,label1='v1,v2,v3'. (default [])";
    };
    allow-metric-labels-manifest = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The path to the manifest file that contains the allow-list mapping. The format of the file is the same as the flag --allow-metric-labels. Note that the flag --allow-metric-labels will override the manifest file.";
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

    # Logs flags
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
    log-text-info-buffer-size = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "[Alpha] In text format with split output streams, the info messages can be buffered for a while to increase performance. The default value of zero bytes disables buffering. The size can be specified as number of bytes (512), multiples of 1000 (1K), multiples of 1024 (2Ki), or powers of those (3M, 4G, 5Mi, 6Gi). Enable the LoggingAlphaOptions feature gate to use this.";
    };
    log-text-split-stream = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "[Alpha] In text format, write error messages to stderr and info messages to stdout. The default is to write a single stream to stdout. Enable the LoggingAlphaOptions feature gate to use this.";
    };
    logging-format = mkOption {
      type = types.nullOr (types.enum [
        "json"
        "text"
      ]);
      default = null;
      description = "Sets the log format. Permitted formats: 'json' (gated by LoggingBetaOptions), 'text'. (default 'text'";
    };
    v = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "number for the log level verbosity";
    };
    vmodule = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A comma-separated list of pattern=N settings for file-filtered logging (only works for text log format)";
    };

    # Traces flags
    tracing-config-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "File with apiserver tracing configuration.";
    };

    # Misc flags
    aggregator-reject-forwarding-redirect = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Aggregator reject forwarding redirect response back to client. (default true)";
    };
    allow-privileged = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true, allow privileged containers. [default=false]";
    };
    enable-aggregator-routing = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Turns on aggregator routing requests to endpoints IP rather than cluster IP.";
    };
    endpoint-reconciler-type = mkOption {
      type = types.nullOr (types.enum [
        "master-count"
        "lease"
        "none"
      ]);
      default = null;
      description = "Use an endpoint reconciler (master-count, lease, none) master-count is deprecated, and will be removed in a future version. (default 'lease')";
    };
    event-ttl = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Amount of time to retain events. (default 1h0m0s)";
    };
    kubelet-certificate-authority = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a cert file for the certificate authority.";
    };
    kubelet-client-certificate = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a client cert file for TLS.";
    };
    kubelet-client-key = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a client key file for TLS.";
    };
    kubelet-preferred-address-types = mkOption {
      type = types.nullOr (types.listOf (types.enum [
        "Hostname"
        "InternalDNS"
        "InternalIP"
        "ExternalDNS"
        "ExternalIP"
      ]));
      default = null;
      description = "List of the preferred NodeAddressTypes to use for kubelet connections. (default [Hostname,InternalDNS,InternalIP,ExternalDNS,ExternalIP])";
    };
    kubelet-timeout = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Timeout for kubelet operations. (default 5s)";
    };
    kubernetes-service-node-port = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "If non-zero, the Kubernetes master service (which apiserver creates/maintains) will be of type NodePort, using this as the value of the port. If zero, the Kubernetes master service will be of type ClusterIP.";
    };
    max-connection-bytes-per-sec = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "If non-zero, throttle each user connection to this number of bytes/sec. Currently only applies to long-running requests.";
    };
    peer-advertise-ip = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "If set and the UnknownVersionInteroperabilityProxy feature gate is enabled, this IP will be used by peer kube-apiservers to proxy requests to this kube-apiserver when the request cannot be handled by the peer due to version skew between the kube-apiservers. This flag is only used in clusters configured with multiple kube-apiservers for high availability. ";
    };
    peer-advertise-port = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "If set and the UnknownVersionInteroperabilityProxy feature gate is enabled, this port will be used by peer kube-apiservers to proxy requests to this kube-apiserver when the request cannot be handled by the peer due to version skew between the kube-apiservers. This flag is only used in clusters configured with multiple kube-apiservers for high availability.";
    };
    peer-ca-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "If set and the UnknownVersionInteroperabilityProxy feature gate is enabled, this file will be used to verify serving certificates of peer kube-apiservers. This flag is only used in clusters configured with multiple kube-apiservers for high availability.";
    };
    proxy-client-cert-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Client certificate used to prove the identity of the aggregator or kube-apiserver when it must call out during a request. This includes proxying requests to a user api-server and calling out to webhook admission plugins. It is expected that this cert includes a signature from the CA in the --requestheader-client-ca-file flag. That CA is published in the 'extension-apiserver-authentication' configmap in the kube-system namespace. Components receiving calls from kube-aggregator should use that CA to perform their half of the mutual TLS verification.";
    };
    proxy-client-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Private key for the client certificate used to prove the identity of the aggregator or kube-apiserver when it must call out during a request. This includes proxying requests to a user api-server and calling out to webhook admission plugins.";
    };
    service-account-signing-key-file = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to the file that contains the current private key of the service account token issuer. The issuer will sign issued ID tokens with this private key.";
    };
    service-cluster-ip-range = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "A CIDR notation IP range from which to assign service cluster IPs. This must not overlap with any IP ranges assigned to nodes or pods. Max of two dual-stack CIDRs is allowed.";
    };
    service-node-port-range = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "A port range to reserve for services with NodePort visibility.  This must not overlap with the ephemeral port range on nodes.  Example: '30000-32767'. Inclusive at both ends of the range. (default 30000-32767)";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.kube-apiserver = {
      inherit description;
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = ''
          ${pkgs.kubernetes}/bin/kube-apiserver \
            ${optionalString (cfg.advertise-address != null) "--advertise-address ${cfg.advertise-address}"} \
            ${
              optionalString (
                cfg.cloud-provider-gce-l7lb-src-cidrs != null
              ) "--cloud-provider-gce-l7lb-src-cidrs \"${concatStringsSep "," cfg.cloud-provider-gce-l7lb-src-cidrs}\""
            } \
            ${
              optionalString (cfg.cors-allowed-origins != null) "--cors-allowed-origins \"${concatStringsSep "," cfg.cors-allowed-origins}\""
            } \
            ${
              optionalString (
                cfg.default-not-ready-toleration-seconds != null
              ) "--default-not-ready-toleration-seconds ${toString cfg.default-not-ready-toleration-seconds}"
            } \
            ${
              optionalString (
                cfg.default-unreachable-toleration-seconds != null
              ) "--default-unreachable-toleration-seconds ${toString cfg.default-unreachable-toleration-seconds}"
            } \
            ${optionalString (cfg.enable-priority-and-fairness != null) "--enable-priority-and-fairness ${boolToString cfg.enable-priority-and-fairness}"} \
            ${optionalString (cfg.external-hostname != null) "--external-hostname ${cfg.external-hostname}"} \
            ${optionalString (cfg.feature-gates != null) "--feature-gates \"${concatStringsSep "," cfg.feature-gates}\""} \
            ${optionalString (cfg.goaway-chance != null) "--goaway-chance ${toString cfg.goaway-chance}"} \
            ${optionalString (cfg.livez-grace-period != null) "--livez-grace-period ${toString cfg.livez-grace-period}"} \
            ${
              optionalString (
                cfg.max-mutating-requests-inflight != null
              ) "--max-mutating-requests-inflight ${toString cfg.max-mutating-requests-inflight}"
            } \
            ${
              optionalString (
                cfg.max-requests-inflight != null
              ) "--max-requests-inflight ${toString cfg.max-requests-inflight}"
            } \
            ${
              optionalString (cfg.min-request-timeout != null) "--min-request-timeout ${toString cfg.min-request-timeout}"
            } \
            ${optionalString (cfg.request-timeout != null) "--request-timeout ${toString cfg.request-timeout}"} \
            ${
              optionalString (
                cfg.shutdown-delay-duration != null
              ) "--shutdown-delay-duration ${toString cfg.shutdown-delay-duration}"
            } \
            ${optionalString (cfg.shutdown-send-retry-after != null) "--shutdown-send-retry-after ${boolToString cfg.shutdown-send-retry-after}"} \
            ${
              optionalString (
                cfg.shutdown-watch-termination-grace-period != null
              ) "--shutdown-watch-termination-grace-period ${toString cfg.shutdown-watch-termination-grace-period}"
            } \
            ${
              optionalString (
                cfg.strict-transport-security-directives != null
              ) "--strict-transport-security-directives \"${concatStringsSep "," cfg.strict-transport-security-directives}\""
            } \
            ${
              optionalString (
                cfg.delete-collection-workers != null
              ) "--delete-collection-workers ${toString cfg.delete-collection-workers}"
            } \
            ${optionalString (cfg.enable-garbage-collector != null) "--enable-garbage-collector ${boolToString cfg.enable-garbage-collector}"} \
            ${optionalString (cfg.encryption-provider-config != null) "--encryption-provider-config ${cfg.encryption-provider-config}"} \
            ${optionalString (cfg.encryption-provider-config-automatic-reload != null) "--encryption-provider-config-automatic-reload ${boolToString cfg.encryption-provider-config-automatic-reload}"} \
            ${optionalString (cfg.etcd-cafile != null) "--etcd-cafile ${cfg.etcd-cafile}"} \
            ${optionalString (cfg.etcd-certfile != null) "--etcd-certfile ${cfg.etcd-certfile}"} \
            ${optionalString (cfg.etcd-compaction-interval != null) "--etcd-compaction-interval ${cfg.etcd-compaction-interval}"} \
            ${optionalString (cfg.etcd-count-metric-poll-period != null) "--etcd-count-metric-poll-period ${cfg.etcd-count-metric-poll-period}"} \
            ${optionalString (cfg.etcd-db-metric-poll-interval != null) "--etcd-db-metric-poll-interval ${cfg.etcd-db-metric-poll-interval}"} \
            ${optionalString (cfg.etcd-healthcheck-timeout != null) "--etcd-healthcheck-timeout ${cfg.etcd-healthcheck-timeout}"} \
            ${optionalString (cfg.etcd-keyfile != null) "--etcd-keyfile ${cfg.etcd-keyfile}"} \
            ${optionalString (cfg.etcd-prefix != null) "--etcd-prefix ${cfg.etcd-prefix}"} \
            ${optionalString (cfg.etcd-readycheck-timeout != null) "--etcd-readycheck-timeout ${cfg.etcd-readycheck-timeout}"} \
            ${optionalString (cfg.etcd-servers != null) "--etcd-servers \"${concatStringsSep "," cfg.etcd-servers}\""} \
            ${optionalString (cfg.etcd-servers-overrides != null) "--etcd-servers-overrides \"${concatStringsSep "," cfg.etcd-servers-overrides}\""} \
            ${optionalString (cfg.lease-reuse-duration-seconds != null) "--lease-reuse-duration-seconds ${toString cfg.lease-reuse-duration-seconds}"} \
            ${optionalString (cfg.storage-backend != null) "--storage-backend ${cfg.storage-backend}"} \
            ${optionalString (cfg.storage-media-type != null) "--storage-media-type ${cfg.storage-media-type}"} \
            ${optionalString (cfg.watch-cache != null) "--watch-cache ${boolToString cfg.watch-cache}"} \
            ${optionalString (cfg.watch-cache-sizes != null) "--watch-cache-sizes \"${concatStringsSep "," cfg.watch-cache-sizes}\""} \
            ${optionalString (cfg.bind-address != null) "--bind-address ${cfg.bind-address}"} \
            ${optionalString (cfg.cert-dir != null) "--cert-dir ${cfg.cert-dir}"} \
            ${optionalString (cfg.http2-max-streams-per-connection != null) "--http2-max-streams-per-connection ${toString cfg.http2-max-streams-per-connection}"} \
            ${optionalString (cfg.permit-address-sharing != null) "--permit-address-sharing ${boolToString cfg.permit-address-sharing}"} \
            ${optionalString (cfg.permit-port-sharing != null) "--permit-port-sharing ${boolToString cfg.permit-port-sharing}"} \
            ${optionalString (cfg.secure-port != null) "--secure-port ${toString cfg.secure-port}"} \
            ${optionalString (cfg.tls-cert-file != null) "--tls-cert-file ${cfg.tls-cert-file}"} \
            ${optionalString (cfg.tls-cipher-suites != null) "--tls-cipher-suites \"${concatStringsSep "," cfg.tls-cipher-suites}\""} \
            ${optionalString (cfg.tls-min-version != null) "--tls-min-version ${cfg.tls-min-version}"} \
            ${optionalString (cfg.tls-private-key-file != null) "--tls-private-key-file ${cfg.tls-private-key-file}"} \
            ${optionalString (cfg.tls-sni-cert-key != null) "--tls-sni-cert-key \"${concatStringsSep "," cfg.tls-sni-cert-key}\""} \
            ${optionalString (cfg.audit-log-batch-buffer-size != null) "--audit-log-batch-buffer-size ${toString cfg.audit-log-batch-buffer-size}"} \
            ${optionalString (cfg.audit-log-batch-max-size != null) "--audit-log-batch-max-size ${toString cfg.audit-log-batch-max-size}"} \
            ${optionalString (cfg.audit-log-batch-max-wait != null) "--audit-log-batch-max-wait ${toString cfg.audit-log-batch-max-wait}"} \
            ${optionalString (cfg.audit-log-batch-throttle-burst != null) "--audit-log-batch-throttle-burst ${toString cfg.audit-log-batch-throttle-burst}"} \
            ${optionalString (cfg.audit-log-batch-throttle-enable != null) "--audit-log-batch-throttle-enable ${boolToString cfg.audit-log-batch-throttle-enable}"} \
            ${optionalString (cfg.audit-log-batch-throttle-qps != null) "--audit-log-batch-throttle-qps ${toString cfg.audit-log-batch-throttle-qps}"} \
            ${optionalString (cfg.audit-log-compress != null) "--audit-log-compress"} \
            ${optionalString (cfg.audit-log-format != null) "--audit-log-format ${cfg.audit-log-format}"} \
            ${optionalString (cfg.audit-log-maxage != null) "--audit-log-maxage ${toString cfg.audit-log-maxage}"} \
            ${optionalString (cfg.audit-log-maxbackup != null) "--audit-log-maxbackup ${toString cfg.audit-log-maxbackup}"} \
            ${optionalString (cfg.audit-log-maxsize != null) "--audit-log-maxsize ${toString cfg.audit-log-maxsize}"} \
            ${optionalString (cfg.audit-log-mode != null) "--audit-log-mode ${cfg.audit-log-mode}"} \
            ${optionalString (cfg.audit-log-path != null) "--audit-log-path ${cfg.audit-log-path}"} \
            ${optionalString (cfg.audit-log-truncate-enabled != null) "--audit-log-truncate-enabled"} \
            ${optionalString (cfg.audit-log-truncate-max-batch-size != null) "--audit-log-truncate-max-batch-size ${toString cfg.audit-log-truncate-max-batch-size}"} \
            ${optionalString (cfg.audit-log-truncate-max-event-size != null) "--audit-log-truncate-max-event-size ${toString cfg.audit-log-truncate-max-event-size}"} \
            ${optionalString (cfg.audit-log-version != null) "--audit-log-version ${cfg.audit-log-version}"} \
            ${optionalString (cfg.audit-policy-file != null) "--audit-policy-file ${cfg.audit-policy-file}"} \
            ${optionalString (cfg.audit-webhook-batch-buffer-size != null) "--audit-webhook-batch-buffer-size ${toString cfg.audit-webhook-batch-buffer-size}"} \
            ${optionalString (cfg.audit-webhook-batch-max-size != null) "--audit-webhook-batch-max-size ${toString cfg.audit-webhook-batch-max-size}"} \
            ${optionalString (cfg.audit-webhook-batch-max-wait != null) "--audit-webhook-batch-max-wait ${toString cfg.audit-webhook-batch-max-wait}"} \
            ${optionalString (cfg.audit-webhook-batch-throttle-burst != null) "--audit-webhook-batch-throttle-burst ${toString cfg.audit-webhook-batch-throttle-burst}"} \
            ${optionalString (cfg.audit-webhook-batch-throttle-enable != null) "--audit-webhook-batch-throttle-enable         ${boolToString cfg.audit-webhook-batch-throttle-enable}"} \
            ${optionalString (cfg.audit-webhook-batch-throttle-qps != null) "--audit-webhook-batch-throttle-qps ${toString cfg.audit-webhook-batch-throttle-qps}"} \
            ${optionalString (cfg.audit-webhook-config-file != null) "--audit-webhook-config-file ${cfg.audit-webhook-config-file}"} \
            ${optionalString (cfg.audit-webhook-initial-backoff != null) "--audit-webhook-initial-backoff ${cfg.audit-webhook-initial-backoff}"} \
            ${optionalString (cfg.audit-webhook-mode != null) "--audit-webhook-mode ${cfg.audit-webhook-mode}"} \
            ${optionalString (cfg.audit-webhook-truncate-enabled != null) "--audit-webhook-truncate-enabled"} \
            ${optionalString (cfg.audit-webhook-truncate-max-batch-size != null) "--audit-webhook-truncate-max-batch-size ${toString cfg.audit-webhook-truncate-max-batch-size}"} \
            ${optionalString (cfg.audit-webhook-truncate-max-event-size != null) "--audit-webhook-truncate-max-event-size ${toString cfg.audit-webhook-truncate-max-event-size}"} \
            ${optionalString (cfg.audit-webhook-version != null) "--audit-webhook-version ${cfg.audit-webhook-version}"} \
            ${optionalString (cfg.contention-profiling != null) "--contention-profiling"} \
            ${optionalString (cfg.debug-socket-path != null) "--debug-socket-path ${cfg.debug-socket-path}"} \
            ${optionalString (cfg.profiling != null) "--profiling ${boolToString cfg.profiling}"} \
            ${optionalString (cfg.anonymous-auth != null) "--anonymous-auth ${boolToString cfg.anonymous-auth}"} \
            ${optionalString (cfg.api-audiences != null) "--api-audiences \"${concatStringsSep "," cfg.api-audiences}\""} \
            ${optionalString (cfg.authentication-config != null) "--authentication-config ${cfg.authentication-config}"} \
            ${optionalString (cfg.authentication-token-webhook-cache-ttl != null) "--authentication-token-webhook-cache-ttl ${cfg.authentication-token-webhook-cache-ttl}"} \
            ${optionalString (cfg.authentication-token-webhook-config-file != null) "--authentication-token-webhook-config-file ${cfg.authentication-token-webhook-config-file}"} \
            ${optionalString (cfg.authentication-token-webhook-version != null) "--authentication-token-webhook-version ${cfg.authentication-token-webhook-version}"} \
            ${optionalString (cfg.client-ca-file != null) "--client-ca-file ${cfg.client-ca-file}"} \
            ${optionalString (cfg.enable-bootstrap-token-auth != null) "--enable-bootstrap-token-auth"} \
            ${optionalString (cfg.oidc-ca-file != null) "--oidc-ca-file ${cfg.oidc-ca-file}"} \
            ${optionalString (cfg.oidc-client-id != null) "--oidc-client-id ${cfg.oidc-client-id}"} \
            ${optionalString (cfg.oidc-groups-claim != null) "--oidc-groups-claim ${cfg.oidc-groups-claim}"} \
            ${optionalString (cfg.oidc-groups-prefix != null) "--oidc-groups-prefix ${cfg.oidc-groups-prefix}"} \
            ${optionalString (cfg.oidc-issuer-url != null) "--oidc-issuer-url ${cfg.oidc-issuer-url}"} \
            ${concatStringsSep " " oidc-required-claim-items} \
            ${optionalString (cfg.oidc-signing-algs != null) "--oidc-signing-algs ${cfg.oidc-signing-algs}"} \
            ${optionalString (cfg.oidc-username-claim != null) "--oidc-username-claim ${cfg.oidc-username-claim}"} \
            ${optionalString (cfg.oidc-username-prefix != null) "--oidc-username-prefix ${cfg.oidc-username-prefix}"} \
            ${optionalString (cfg.requestheader-allowed-names != null) "--requestheader-allowed-names \"${concatStringsSep "," cfg.requestheader-allowed-names}\""} \
            ${optionalString (cfg.requestheader-client-ca-file != null) "--requestheader-client-ca-file ${cfg.requestheader-client-ca-file}"} \
            ${optionalString (cfg.requestheader-extra-headers-prefix != null) "--requestheader-extra-headers-prefix \"${concatStringsSep "," cfg.requestheader-extra-headers-prefix}\""} \
            ${optionalString (cfg.requestheader-group-headers != null) "--requestheader-group-headers \"${concatStringsSep "," cfg.requestheader-group-headers}\""} \
            ${optionalString (cfg.requestheader-username-headers != null) "--requestheader-username-headers \"${concatStringsSep "," cfg.requestheader-username-headers}\""} \
            ${optionalString (cfg.service-account-extend-token-expiration != null) "--service-account-extend-token-expiration ${boolToString cfg.service-account-extend-token-expiration}"} \
            ${optionalString (cfg.service-account-issuer != null) "--service-account-issuer ${cfg.service-account-issuer}"} \
            ${optionalString (cfg.service-account-jwks-uri != null) "--service-account-jwks-uri ${cfg.service-account-jwks-uri}"} \
            ${optionalString (cfg.service-account-key-file != null) "--service-account-key-file ${cfg.service-account-key-file}"} \
            ${optionalString (cfg.service-account-lookup != null) "--service-account-lookup ${boolToString cfg.service-account-lookup}"} \
            ${optionalString (cfg.service-account-max-token-expiration != null) "--service-account-max-token-expiration ${cfg.service-account-max-token-expiration}"} \
            ${optionalString (cfg.token-auth-file != null) "--token-auth-file ${cfg.token-auth-file}"} \
            ${optionalString (cfg.authorization-config != null) "--authorization-config ${cfg.authorization-config}"} \
            ${optionalString (cfg.authorization-mode != null) "--authorization-mode \"${concatStringsSep "," cfg.authorization-mode}\""} \
            ${optionalString (cfg.authorization-policy-file != null) "--authorization-policy-file ${cfg.authorization-policy-file}"} \
            ${optionalString (cfg.authorization-webhook-cache-authorized-ttl != null) "--authorization-webhook-cache-authorized-ttl ${cfg.authorization-webhook-cache-authorized-ttl}"} \
            ${optionalString (cfg.authorization-webhook-cache-unauthorized-ttl != null) "--authorization-webhook-cache-unauthorized-ttl ${cfg.authorization-webhook-cache-unauthorized-ttl}"} \
            ${optionalString (cfg.authorization-webhook-config-file != null) "--authorization-webhook-config-file ${cfg.authorization-webhook-config-file}"} \
            ${optionalString (cfg.authorization-webhook-version != null) "--authorization-webhook-version ${cfg.authorization-webhook-version}"} \
            ${optionalString (cfg.runtime-config != null) "--runtime-config \"${concatStringsSep "," cfg.runtime-config}\""} \
            ${optionalString (cfg.egress-selector-config-file != null) "--egress-selector-config-file ${cfg.egress-selector-config-file}"} \
            ${optionalString (cfg.admission-control != null) "--admission-control \"${concatStringsSep "," cfg.admission-control}\""} \
            ${optionalString (cfg.admission-control-config-file != null) "--admission-control-config-file ${cfg.admission-control-config-file}"} \
            ${optionalString (cfg.disable-admission-plugins != null) "--disable-admission-plugins \"${concatStringsSep "," cfg.disable-admission-plugins}\""} \
            ${optionalString (cfg.enable-admission-plugins != null) "--enable-admission-plugins \"${concatStringsSep "," cfg.enable-admission-plugins}\""} \
            ${optionalString (cfg.allow-metric-labels != null) "--allow-metric-labels \"${concatStringsSep "," cfg.allow-metric-labels}\""} \
            ${optionalString (cfg.allow-metric-labels-manifest != null) "--allow-metric-labels-manifest ${cfg.allow-metric-labels-manifest}"} \
            ${optionalString (cfg.disabled-metrics != null) "--disabled-metrics \"${concatStringsSep "," cfg.disabled-metrics}\""} \
            ${optionalString (cfg.show-hidden-metrics-for-version != null) "--show-hidden-metrics-for-version ${cfg.show-hidden-metrics-for-version}"} \
            ${optionalString (cfg.log-flush-frequency != null) "--log-flush-frequency ${cfg.log-flush-frequency}"} \
            ${optionalString (cfg.log-json-info-buffer-size != null) "--log-json-info-buffer-size ${cfg.log-json-info-buffer-size}"} \
            ${optionalString (cfg.log-json-split-stream != null) "--log-json-split-stream"} \
            ${optionalString (cfg.log-text-info-buffer-size != null) "--log-text-info-buffer-size ${cfg.log-text-info-buffer-size}"} \
            ${optionalString (cfg.log-text-split-stream != null) "--log-text-split-stream"} \
            ${optionalString (cfg.logging-format != null) "--logging-format ${cfg.logging-format}"} \
            ${optionalString (cfg.v != null) "--v ${toString cfg.v}"} \
            ${optionalString (cfg.vmodule != null) "--vmodule \"${concatStringsSep "," cfg.vmodule}\""} \
            ${optionalString (cfg.tracing-config-file != null) "--tracing-config-file ${cfg.tracing-config-file}"} \
            ${optionalString (cfg.aggregator-reject-forwarding-redirect != null) "--aggregator-reject-forwarding-redirect ${toString cfg.aggregator-reject-forwarding-redirect}"} \
            ${optionalString (cfg.allow-privileged != null) "--allow-privileged ${boolToString cfg.allow-privileged}"} \
            ${optionalString (cfg.enable-aggregator-routing != null) "--enable-aggregator-routing"} \
            ${optionalString (cfg.endpoint-reconciler-type != null) "--endpoint-reconciler-type ${cfg.endpoint-reconciler-type}"} \
            ${optionalString (cfg.event-ttl != null) "--event-ttl ${cfg.event-ttl}"} \
            ${optionalString (cfg.kubelet-certificate-authority != null) "--kubelet-certificate-authority ${cfg.kubelet-certificate-authority}"} \
            ${optionalString (cfg.kubelet-client-certificate != null) "--kubelet-client-certificate ${cfg.kubelet-client-certificate}"} \
            ${optionalString (cfg.kubelet-client-key != null) "--kubelet-client-key ${cfg.kubelet-client-key}"} \
            ${optionalString (cfg.kubelet-preferred-address-types != null) "--kubelet-preferred-address-types \"${concatStringsSep "," cfg.kubelet-preferred-address-types}\""} \
            ${optionalString (cfg.kubelet-timeout != null) "--kubelet-timeout ${cfg.kubelet-timeout}"} \
            ${optionalString (cfg.kubernetes-service-node-port != null) "--kubernetes-service-node-port ${toString cfg.kubernetes-service-node-port}"} \
            ${optionalString (cfg.max-connection-bytes-per-sec != null) "--max-connection-bytes-per-sec ${toString cfg.max-connection-bytes-per-sec}"} \
            ${optionalString (cfg.peer-advertise-ip != null) "--peer-advertise-ip ${cfg.peer-advertise-ip}"} \
            ${optionalString (cfg.peer-advertise-port != null) "--peer-advertise-port ${toString cfg.peer-advertise-port}"} \
            ${optionalString (cfg.peer-ca-file != null) "--peer-ca-file ${cfg.peer-ca-file}"} \
            ${optionalString (cfg.proxy-client-cert-file != null) "--proxy-client-cert-file ${cfg.proxy-client-cert-file}"} \
            ${optionalString (cfg.proxy-client-key-file != null) "--proxy-client-key-file ${cfg.proxy-client-key-file}"} \
            ${optionalString (cfg.service-account-signing-key-file != null) "--service-account-signing-key-file ${cfg.service-account-signing-key-file}"} \
            ${optionalString (cfg.service-cluster-ip-range != null) "--service-cluster-ip-range ${cfg.service-cluster-ip-range}"} \
            ${optionalString (cfg.service-node-port-range != null) "--service-node-port-range ${cfg.service-node-port-range}"}
            '';
        };
    };
  };
}
