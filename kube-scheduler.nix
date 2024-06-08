{
  config,
  pkgs,
  lib,
  ...
}:

with lib;

let
  cfg = config.services.kube-scheduler;
in
{
  options.services.kube-scheduler = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "The Kubernetes scheduler is a control plane process which assigns Pods to Nodes. The scheduler determines which Nodes are valid placements for each Pod in the scheduling queue according to constraints and available resources. The scheduler then ranks each valid Node and binds the Pod to a suitable Node. Multiple different schedulers may be used within a cluster; kube-scheduler is the reference implementation. See https://kubernetes.io/docs/concepts/scheduling-eviction/ for more information about scheduling and the kube-scheduler component.";
    };

    # Misc flags
    configFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The path to the configuration file.";
    };

    master = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The address of the Kubernetes API server (overrides any value in kubeconfig)";
    };

    write-config-to = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "If set, write the configuration values to this file and exit.";
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
      description = "true, SO_REUSEADDR will be used when binding the port. This allows binding to wildcard IPs like 0.0.0.0 and specific IPs in parallel, and it avoids waiting for the kernel to release sockets in TIME_WAIT state. [default=false]";
    };

  permit-port-sharing = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "true, SO_REUSEPORT will be used when binding the port, which allows more than one instance to bind on the same address and port. [default=false]";
    };

  secure-port = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The port on which to serve HTTPS with authentication and authorization. If 0, don't serve HTTPS at all. (default 10259)";
    };

  tls-cert-file = mkOption {
      type = types.nullOr types.str;
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

  tls-min-version = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Minimum TLS version supported. Possible values: VersionTLS10, VersionTLS11, VersionTLS12, VersionTLS13";
    };

  tls-private-key-file = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "File containing the default x509 private key matching --tls-cert-file.";
    };

  tls-sni-cert-key = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A pair of x509 certificate and private key file paths, optionally suffixed with a list of domain patterns which are fully qualified domain names, possibly with prefixed wildcard segments. The domain patterns also allow IP addresses, but IPs should only be used if the apiserver has visibility to the IP address requested by a client. If no domain patterns are provided, the names of the certificate are extracted. Non-wildcard matches trump over wildcard matches, explicit domain patterns trump over extracted names. For multiple key/certificate pairs, use the --tls-sni-cert-key multiple times. Examples: 'example.crt,example.key' or 'foo.crt,foo.key:*.foo.com,foo.com'. (default [])";
    };

  # Authentication flags
  authentication-kubeconfig = mkOption {
      type = types.nullOr types.str;
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
      description = "If true, failures to look up missing authentication configuration from the cluster are not considered fatal. Note that this can result in authentication that treats all requests as anonymous. (default true)";
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

  # Authorization flags
  authorization-always-allow-paths = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "A list of HTTP paths to skip during authorization, i.e. these are authorized without contacting the 'core' kubernetes server. (default [/healthz,/readyz,/livez])";
    };

  authorization-kubeconfig = mkOption {
      type = types.nullOr types.str;
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

   # Deprecated flags
  contention-profiling = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "DEPRECATED: enable block profiling, if profiling is enabled. This parameter is ignored if a config file is specified in --config. (default true)";
    };

  kube-api-burst = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "DEPRECATED: burst to use while talking with kubernetes apiserver. This parameter is ignored if a config file is specified in --config. (default 100)";
    };

  kube-api-content-type = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "DEPRECATED: content type of requests sent to apiserver. This parameter is ignored if a config file is specified in --config. (default 'application/vnd.kubernetes.protobuf')";
    };

  kube-api-qps = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "DEPRECATED: QPS to use while talking with kubernetes apiserver. This parameter is ignored if a config file is specified in --config. (default 50)";
    };

  kubeconfig = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "DEPRECATED: path to kubeconfig file with authorization and master location information. This parameter is ignored if a config file is specified in --config.";
    };

  pod-max-in-unschedulable-pods-duration = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "DEPRECATED: the maximum time a pod can stay in unschedulablePods. If a pod stays in unschedulablePods for longer than this value, the pod will be moved from unschedulablePods to backoffQ or activeQ. This flag is deprecated and will be removed in 1.26 (default 5m0s)";
    };

  profiling = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "DEPRECATED: enable profiling via web interface host:port/debug/pprof/. This parameter is ignored if a config file is specified in --config. (default true)";
    };

  # Leader election flags
  leader-elect = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "a leader election client and gain leadership before executing the main loop. Enable this when running replicated components for high availability. (default true)";
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
      type = types.nullOr (types.enum [
        "leases"
        "endpointsleases"
        "configmapsleases"
      ]);
      default = null;
      description = "The type of resource object that is used for locking during leader election. Supported options are 'leases', 'endpointsleases' and 'configmapsleases'. (default 'leases')";
    };

  leader-elect-resource-name = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The name of resource object that is used for locking during leader election. (default 'kube-scheduler')";
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

  # Metrics flags
  allow-metric-labels = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "The map from metric-label to value allow-list of this label. The key's format is <MetricName>,<LabelName>. The value's format is <allowed_value>,<allowed_value>...e.g. metric1,label1='v1,v2,v3', metric1,label2='v1,v2,v3' metric2,label1='v1,v2,v3'. (default [])";
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
      description = "In JSON format, write error messages to stderr and info messages to stdout. The default is to write a single stream to stdout. Enable the LoggingAlphaOptions feature gate to use this.";
    };

  logging-format = mkOption {
      type = types.nullOr (types.enum [ "json" "text" ]);
      default = null;
      description = "Sets the log format. Permitted formats: 'json' (gated by LoggingBetaOptions), 'text'. (default 'text')";
    };

  v = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "number for the log level verbosity";
    };

  vmodule = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "comma-separated list of pattern=N settings for file-filtered logging (only works for text log format)";
    };
  };

  config = mkIf cfg.enable {
    systemd.services.kube-scheduler = {
      description = "The Kubernetes scheduler is a control plane process which assigns Pods to Nodes. The scheduler determines which Nodes are valid placements for each Pod in the scheduling queue according to constraints and available resources. The scheduler then ranks each valid Node and binds the Pod to a suitable Node. Multiple different schedulers may be used within a cluster; kube-scheduler is the reference implementation. See https://kubernetes.io/docs/concepts/scheduling-eviction/ for more information about scheduling and the kube-scheduler component.";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = ''
          ${pkgs.coreutils}/bin/echo ${pkgs.kubernetes}/bin/kube-scheduler \
            ${optionalString (cfg.config != null) "--config ${cfg.config}"} \
            ${optionalString (cfg.master != null) "--master ${cfg.master}"} \
            ${optionalString (cfg.write-config-to != null) "--write-config-to ${cfg.write-config-to}"} \
            ${optionalString (cfg.bind-address != null) "--bind-address ${cfg.bind-address}"} \
            ${optionalString (cfg.cert-dir != null) "--cert-dir ${cfg.cert-dir}"} \
            ${optionalString (cfg.http2-max-streams-per-connection != null) "--http2-max-streams-per-connection ${cfg.http2-max-streams-per-connection}"} \
            ${optionalString (cfg.permit-address-sharing != null) "--permit-address-sharing ${cfg.permit-address-sharing                }"} \
            ${optionalString (cfg.permit-port-sharing != null) "--permit-port-sharing ${cfg.permit-port-sharing}"} \
            ${optionalString (cfg.secure-port != null) "--secure-port ${cfg.secure-port}"} \
            ${optionalString (cfg.tls-cert-file != null) "--tls-cert-file ${cfg.tls-cert-file}"} \
            ${optionalString (cfg.tls-cipher-suites != null) "--tls-cipher-suites \"${concatStringsSep "," cfg.tls-cipher-suites}\""} \
            ${optionalString (cfg.tls-min-version != null) "--tls-min-version ${cfg.tls-min-version}"} \
            ${optionalString (cfg.tls-private-key-file != null) "--tls-private-key-file ${cfg.tls-private-key-file}"} \
            ${optionalString (cfg.tls-sni-cert-key != null) "--tls-sni-cert-key \"${concatStringsSep "," cfg.tls-sni-cert-key}\""} \
            ${optionalString (cfg.authentication-kubeconfig != null) "--authentication-kubeconfig ${cfg.authentication-kubeconfig}"} \
            ${optionalString (cfg.authentication-skip-lookup != null) "--authentication-skip-lookup {cfg.authentication-skip-lookup}"} \
            ${optionalString (cfg.authentication-token-webhook-cache-ttl != null) "--authentication-token-webhook-cache-ttl ${cfg.authentication-token-webhook-cache-ttl}"} \
            ${optionalString (cfg.authentication-tolerate-lookup-failure != null) "--authentication-tolerate-lookup-failure ${cfg.authentication-tolerate-lookup-failure}"} \
            ${optionalString (cfg.client-ca-file != null) "--client-ca-file ${cfg.client-ca-file}"} \
            ${optionalString (cfg.requestheader-allowed-names != null) "--requestheader-allowed-names \"${concatStringsSep "," cfg.requestheader-allowed-names}\""} \
            ${optionalString (cfg.requestheader-client-ca-file != null) "--requestheader-client-ca-file ${cfg.requestheader-client-ca-file}"} \
            ${optionalString (cfg.requestheader-extra-headers-prefix != null) "--requestheader-extra-headers-prefix  \"${concatStringsSep "," cfg.requestheader-extra-headers-prefix}\""} \
            ${optionalString (cfg.requestheader-group-headers != null) "--requestheader-group-headers \"${concatStringsSep "," cfg.requestheader-group-headers}\""} \
            ${optionalString (cfg.requestheader-username-headers != null) "--requestheader-username-headers \"${concatStringsSep "," cfg.requestheader-username-headers}\""} \
            ${optionalString (cfg.authorization-always-allow-paths != null) "--authorization-always-allow-paths \"${concatStringsSep "," cfg.authorization-always-allow-paths}\""} \
            ${optionalString (cfg.authorization-kubeconfig != null) "--authorization-kubeconfig ${cfg.authorization-kubeconfig}"} \
            ${optionalString (cfg.authorization-webhook-cache-authorized-ttl != null) "--authorization-webhook-cache-authorized-ttl ${cfg.authorization-webhook-cache-authorized-ttl}"} \
            ${optionalString (cfg.authorization-webhook-cache-unauthorized-ttl != null) "--authorization-webhook-cache-unauthorized-ttl ${cfg.authorization-webhook-cache-unauthorized-ttl}"} \
            ${optionalString (cfg.contention-profiling != null) "--contention-profiling ${cfg.contention-profiling}"} \
            ${optionalString (cfg.kube-api-burst != null) "--kube-api-burst ${cfg.kube-api-burst}"} \
            ${optionalString (cfg.kube-api-content-type != null) "--kube-api-content-type ${cfg.kube-api-content-type}"} \
            ${optionalString (cfg.kube-api-qps != null) "--kube-api-qps ${cfg.kube-api-qps}"} \
            ${optionalString (cfg.kubeconfig != null) "--kubeconfig ${cfg.kubeconfig}"} \
            ${optionalString (cfg.pod-max-in-unschedulable-pods-duration != null) "--pod-max-in-unschedulable-pods-duration ${cfg.pod-max-in-unschedulable-pods-duration}"} \
            ${optionalString (cfg.profiling != null) "--profiling ${cfg.profiling}"} \
            ${optionalString (cfg.leader-elect != null) "--leader-elect ${cfg.leader-elect}"} \
            ${optionalString (cfg.leader-elect-lease-duration != null) "--leader-elect-lease-duration ${cfg.leader-elect-lease-duration}"} \
            ${optionalString (cfg.leader-elect-renew-deadline != null) "--leader-elect-renew-deadline ${cfg.leader-elect-renew-deadline}"} \
            ${optionalString (cfg.leader-elect-resource-lock != null) "--leader-elect-resource-lock ${cfg.leader-elect-resource-lock}"} \
            ${optionalString (cfg.leader-elect-resource-name != null) "--leader-elect-resource-name ${cfg.leader-elect-resource-name}"} \
            ${optionalString (cfg.leader-elect-resource-namespace != null) "--leader-elect-resource-namespace ${cfg.leader-elect-resource-namespace}"} \
            ${optionalString (cfg.leader-elect-retry-period != null) "--leader-elect-retry-period ${cfg.feature-gatesleader-elect-retry-period}"} \
            ${optionalString (cfg.feature-gates != null) "--feature-gates \"${concatStringsSep "," cfg.feature-gates}\""} \
            ${optionalString (cfg.allow-metric-labels != null) "--allow-metric-labels \"${concatStringsSep "," cfg.allow-metric-labels}\""} \
            ${optionalString (cfg.disabled-metrics != null) "--disabled-metrics \"${concatStringsSep "," cfg.disabled-metrics}\""} \
            ${optionalString (cfg.show-hidden-metrics-for-version != null) "--show-hidden-metrics-for-version ${cfg.show-hidden-metrics-for-version}"} \
            ${optionalString (cfg.log-flush-frequency != null) "--log-flush-frequency ${cfg.log-flush-frequency}"} \
            ${optionalString (cfg.log-json-info-buffer-size != null) "--log-json-info-buffer-size ${cfg.log-json-info-buffer-size}"} \
            ${optionalString (cfg.log-json-split-stream != null) "--log-json-split-stream ${cfg.log-json-split-stream}"} \
            ${optionalString (cfg.logging-format != null) "--logging-format ${cfg.logging-format}"} \
            ${optionalString (cfg.v != null) "--v ${cfg.v}"} \
            ${optionalString (cfg.vmodule != null) "--vmodule \"${concatStringsSep "," cfg.vmodule}\""}
            '';
      };
    };
  };
}
