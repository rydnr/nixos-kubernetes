{
  config,
  pkgs,
  lib,
  nixpkgs,
  ...
}:

with lib;

let
  cfg = config.services.raw-kube-proxy;
  mkKubeConfig = name: attrs: pkgs.writeText "${name}-kubeconfig" (builtins.toJSON {
    apiVersion = "v1";
    kind = "Config";
    clusters = [{
      name = "local";
      cluster.certificate-authority = attrs.caCrtFile;
      cluster.server = attrs.server;
    }];
    users = [{
      inherit name;
      user = {
        client-certificate = attrs.certCrtFile;
        client-key = attrs.certKeyFile;
      };
    }];
    contexts = [{
      context = {
        cluster = "local";
        user = name;
      };
      current-context = "local";
    }];
  });
  mkKubeConfigOptions = prefix: {
    server = mkOption {
      description = "${prefix} kube-apiserver server address.";
      type = types.str;
    };
    caCrtFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the CA file.";
    };
    caKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the CA key file.";
    };
    certCrtFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the certificate.";
    };
    certKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = "Path to the certificate key file.";
    };
  };
  generatedKubeConfig = mkKubeConfig "kube-proxy" cfg.kubeConfigOpts // { certCrtFile = cfg.certCrtFile; certKeyFile = cfg.certKeyFile; };
  kubeConfigFile = if cfg.kubeconfig != null then cfg.kubeconfig else generatedKubeConfig;

  boolToString = b: if b then "true" else "false";
  description = "The Kubernetes network proxy runs on each node. This reflects services as defined in the Kubernetes API on each node and can do simple TCP, UDP, and SCTP stream forwarding or round robin TCP, UDP, and SCTP forwarding across a set of backends. Service cluster IPs and ports are currently found through Docker-links-compatible environment variables specifying ports opened by the service proxy. There is an optional addon that provides cluster DNS for these cluster IPs. The user must create a service with the apiserver API to configure the proxy.";
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
  options.services.raw-kube-proxy = {
    enable = mkOption {
      type = types.bool;
      default = false;
      inherit description;
    };
    bind-address = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address for the proxy server to serve on (set to '0.0.0.0' for all IPv4 interfaces and '::' for all IPv6 interfaces). This parameter is ignored if a config file is specified by --config. (default 0.0.0.0)";
    };
    bind-address-hard-fail = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true kube-proxy will treat failure to bind to a port as fatal and exit";
    };
    boot-id-file = mkOption {
      type = types.nullOr (types.listOf types.path);
      default = null;
      description = "List of files to check for boot-id. Use the first one that exists. (default '/proc/sys/kernel/random/boot_id')";
    };
    cleanup = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true cleanup iptables and ipvs rules and exit.";
    };
    cluster-cidr = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The CIDR range of pods in the cluster. When configured, traffic sent to a Service cluster IP from outside this range will be masqueraded and traffic sent from pods to an external LoadBalancer IP will be directed to the respective cluster IP instead. For dual-stack clusters, a comma-separated list is accepted with at least one CIDR per IP family (IPv4 and IPv6). This parameter is ignored if a config file is specified by --config.";
    };
    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "The path to the configuration file.";
    };
    config-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "How often configuration from the apiserver is refreshed.  Must be greater than 0. (default 15m0s)";
    };

    conntrack-max-per-core = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Maximum number of NAT connections to track per CPU core (0 to leave the limit as-is and ignore conntrack-min). (default 32768)";
    };

    conntrack-min = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Minimum number of conntrack entries to allocate, regardless of conntrack-max-per-core (set conntrack-max-per-core=0 to leave the limit as-is). (default 131072)";
    };

    conntrack-tcp-timeout-close-wait = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "NAT timeout for TCP connections in the CLOSE_WAIT state (default 1h0m0s)";
    };

    conntrack-tcp-timeout-established = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Idle timeout for established TCP connections (0 to leave as-is) (default 24h0m0s)";
    };

    detect-local-mode = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Mode to use to detect local traffic. This parameter is ignored if a config file is specified by --config.";
    };

    feature-gates = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = featureGatesDescription;
    };

    healthz-bind-address = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address with port for the health check server to serve on (set to '0.0.0.0:10256' for all IPv4 interfaces and '[::]:10256' for all IPv6 interfaces). Set empty to disable. This parameter is ignored if a config file is specified by --config. (default 0.0.0.0:10256)";
    };

    hostname-override = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "If non-empty, will use this string as identification instead of the actual hostname.";
    };

    iptables-localhost-nodeports = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If false Kube-proxy will disable the legacy behavior of allowing NodePort services to be accessed via localhost, This only applies to iptables mode and ipv4. (default true)";
    };

    iptables-masquerade-bit = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "If using the pure iptables proxy, the bit of the fwmark space to mark packets requiring SNAT with.  Must be within the range [0, 31]. (default 14)";
    };

    iptables-min-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The minimum interval of how often the iptables rules can be refreshed as endpoints and services change (e.g. '5s', '1m', '2h22m'). (default 1s)";
    };

    iptables-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The maximum interval of how often iptables rules are refreshed (e.g. '5s', '1m', '2h22m').  Must be greater than 0. (default 30s)";
    };

    ipvs-exclude-cidrs = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A list of CIDR's which the ipvs proxier should not touch when cleaning up IPVS rules.";
    };

    ipvs-min-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The minimum interval of how often the ipvs rules can be refreshed as endpoints and services change (e.g. '5s', '1m', '2h22m').";
    };

    ipvs-scheduler = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The ipvs scheduler type when proxy mode is ipvs";
    };

    ipvs-strict-arp = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "Enable strict ARP by setting arp_ignore to 1 and arp_announce to 2";
    };

    ipvs-sync-period = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The maximum interval of how often ipvs rules are refreshed (e.g. '5s', '1m', '2h22m').  Must be greater than 0. (default 30s)";
    };

    ipvs-tcp-timeout = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The timeout for idle IPVS TCP connections, 0 to leave as-is. (e.g. '5s', '1m', '2h22m').";
    };

    ipvs-tcpfin-timeout = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The timeout for IPVS TCP connections after receiving a FIN packet, 0 to leave as-is. (e.g. '5s', '1m', '2h22m').";
    };

    ipvs-udp-timeout = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The timeout for IPVS UDP packets, 0 to leave as-is. (e.g. '5s', '1m', '2h22m').";
    };

    kube-api-burst = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Burst to use while talking with kubernetes apiserver (default 10)";
    };

    kube-api-content-type = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Content type of requests sent to apiserver. (default 'application/vnd.kubernetes.protobuf')";
    };

    kube-api-qps = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "QPS to use while talking with kubernetes apiserver (default 5)";
    };

    kubeconfig = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to kubeconfig file with authorization information (the master location can be overridden by the master flag).";
    };

    kubeConfigOpts = mkKubeConfigOptions "raw-kube-proxy";

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
      type = types.nullOr (types.enum ["json" "text"]);
      default = null;
      description = "Sets the log format. Permitted formats: 'json' (gated by LoggingBetaOptions), 'text'. (default 'text')";
    };

    machine-id-file = mkOption {
      type = types.nullOr (types.listOf types.path);
      default = null;
      description = "List of files to check for machine-id. Use the first one that exists. (default  [ /etc/machine-id /var/lib/dbus/machine-id ])";
    };

    masquerade-all = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If using the pure iptables proxy, SNAT all traffic sent via Service cluster IPs (this not commonly needed)";
    };

    master = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The address of the Kubernetes API server (overrides any value in kubeconfig)";
    };

    metrics-bind-address = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The IP address with port for the metrics server to serve on (set to '0.0.0.0:10249' for all IPv4 interfaces and '[::]:10249' for all IPv6 interfaces). Set empty to disable. This parameter is ignored if a config file is specified by --config. (default 127.0.0.1:10249)";
    };

    nodeport-addresses = mkOption {
      type = types.nullOr (types.listOf types.str);
      default = null;
      description = "A string slice of values which specify the addresses to use for NodePorts. Values may be valid IP blocks (e.g. 1.2.3.0/24, 1.2.3.4/32). The default empty string slice ([]) means to use all local addresses. This parameter is ignored if a config file is specified by --config.";
    };

    oom-score-adj = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "The oom-score-adj value for kube-proxy process. Values must be within the range [-1000, 1000]. This parameter is ignored if a config file is specified by --config. (default -999)";
    };

    pod-bridge-interface = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "A bridge interface name in the cluster. Kube-proxy considers traffic as local if originating from an interface which matches the value. This argument should be set if DetectLocalMode is set to BridgeInterface.";
    };

    pod-interface-name-prefix = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "An interface prefix in the cluster. Kube-proxy considers traffic as local if originating from interfaces that match the given prefix. This argument should be set if DetectLocalMode is set to InterfaceNamePrefix.";
    };

    profiling = mkOption {
      type = types.nullOr types.bool;
      default = null;
      description = "If true enables profiling via web interface on /debug/pprof handler. This parameter is ignored if a config file is specified by --config.";
    };

    proxy-mode = mkOption {
      type = types.nullOr (types.enum [ "iptables" "ipvs" ]);
      default = null;
      description = "Which proxy mode to use: on Linux this can be 'iptables' (default) or 'ipvs'. On Windows the only supported value is 'kernelspace'.This parameter is ignored if a config file is specified by --config.";
    };

    proxy-port-range = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "port-Range of host ports (beginPort-endPort, single port or beginPort+offset, inclusive) that may be consumed in order to proxy service traffic. If (unspecified, 0, or 0-0) then ports will be randomly chosen.";
    };

    show-hidden-metrics-for-version = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "The previous version for which you want to show hidden metrics. Only the previous minor version is meaningful, other values will not be allowed. The format is <major>.<minor>, e.g.: '1.16'. The purpose of this format is make sure you have the opportunity to notice if the next release hides additional metrics, rather than being surprised when they are permanently removed in the release after that. This parameter is ignored if a config file is specified by --config.";
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
  };

  config = mkIf cfg.enable {
    systemd.services.raw-kube-proxy = lib.mkForce {
      inherit description;
      # wantedBy = [ "raw-kubernetes.target" ];
      # after = [ "raw-kube-apiserver.service" ];
      path = with pkgs; [ iptables conntrack-tools ];

      serviceConfig = {
        Slice = "raw-kubernetes.slice";
        ExecStart = ''
          ${pkgs.kubernetes}/bin/kube-proxy \
            ${optionalString (cfg.bind-address != null) "--bind-address \"${toString cfg.bind-address}\""} \
            ${optionalString (cfg.bind-address-hard-fail != null) "--bind-address-hard-fail \"${boolToString cfg.bind-address-hard-fail}\""} \
            ${optionalString (cfg.boot-id-file != null) "--boot-id-file \"${concatStringsSep "," cfg.boot-id-file}\""} \
            ${optionalString (cfg.cleanup != null) "--cleanup \"${boolToString cfg.cleanup}\""} \
            ${optionalString (cfg.cluster-cidr != null) "--cluster-cidr \"${toString cfg.cluster-cidr}\""} \
            ${optionalString (cfg.configFile != null) "--config \"${toString cfg.configFile}\""} \
            ${optionalString (cfg.config-sync-period != null) "--config-sync-period \"${toString cfg.config-sync-period}\""} \
            ${optionalString (cfg.conntrack-max-per-core != null) "--conntrack-max-per-core \"${toString cfg.conntrack-max-per-core}\""} \
            ${optionalString (cfg.conntrack-min != null) "--conntrack-min \"${toString cfg.conntrack-min}\""} \
            ${optionalString (cfg.conntrack-tcp-timeout-close-wait != null) "--conntrack-tcp-timeout-close-wait \"${toString cfg.conntrack-tcp-timeout-close-wait}\""} \
            ${optionalString (cfg.conntrack-tcp-timeout-established != null) "--conntrack-tcp-timeout-established \"${toString cfg.conntrack-tcp-timeout-established}\""} \
            ${optionalString (cfg.detect-local-mode != null) "--detect-local-mode \"${toString cfg.detect-local-mode}\""} \
            ${optionalString (cfg.feature-gates != null) "--feature-gates \"${concatStringsSep "," cfg.feature-gates}\""} \
            ${optionalString (cfg.healthz-bind-address != null) "--config.healthz-bind-address \"${toString cfg.healthz-bind-address}\""} \
            ${optionalString (cfg.hostname-override != null) "--hostname-override \"${toString cfg.hostname-override}\""} \
            ${optionalString (cfg.iptables-localhost-nodeports != null) "--iptables-localhost-nodeports \"${boolToString cfg.iptables-localhost-nodeports}\""} \
            ${optionalString (cfg.iptables-masquerade-bit != null) "--iptables-masquerade-bit \"${toString cfg.iptables-masquerade-bit}\""} \
            ${optionalString (cfg.iptables-min-sync-period != null) "--iptables-min-sync-period \"${toString cfg.iptables-min-sync-period}\""} \
            ${optionalString (cfg.iptables-sync-period != null) "--iptables-sync-period \"${toString cfg.iptables-sync-period}\""} \
            ${optionalString (cfg.ipvs-exclude-cidrs != null) "--ipvs-exclude-cidrs \"${concatStringsSep "," cfg.ipvs-exclude-cidrs}\""} \
            ${optionalString (cfg.ipvs-min-sync-period != null) "--ipvs-min-sync-period \"${toString cfg.ipvs-min-sync-period}\""} \
            ${optionalString (cfg.ipvs-scheduler != null) "--ipvs-scheduler \"${toString cfg.ipvs-scheduler}\""} \
            ${optionalString (cfg.ipvs-strict-arp != null) "--ipvs-strict-arp"} \
            ${optionalString (cfg.ipvs-sync-period != null) "--ipvs-sync-period \"${toString cfg.ipvs-sync-period}\""} \
            ${optionalString (cfg.ipvs-tcp-timeout != null) "--ipvs-tcp-timeout \"${toString cfg.ipvs-tcp-timeout}\""} \
            ${optionalString (cfg.ipvs-tcpfin-timeout != null) "--ipvs-tcpfin-timeout \"${toString cfg.ipvs-tcpfin-timeout}\""} \
            ${optionalString (cfg.ipvs-udp-timeout != null) "--ipvs-udp-timeout \"${toString cfg.ipvs-udp-timeout}\""} \
            ${optionalString (cfg.kube-api-burst != null) "--kube-api-burst \"${toString cfg.kube-api-burst}\""} \
            ${optionalString (cfg.kube-api-content-type != null) "--kube-api-content-type \"${toString cfg.kube-api-content-type}\""} \
            ${optionalString (cfg.kube-api-qps != null) "--kube-api-qps \"${toString cfg.kube-api-qps}\""} \
            --kubeconfig "${toString kubeConfigFile}" \
            ${optionalString (cfg.log-flush-frequency != null) "--log-flush-frequency \"${toString cfg.log-flush-frequency}\""} \
            ${optionalString (cfg.log-json-info-buffer-size != null) "--log-json-info-buffer-size \"${toString cfg.log-json-info-buffer-size}\""} \
            ${optionalString (cfg.log-json-split-stream != null) "--log-json-split-stream"} \
            ${optionalString (cfg.logging-format != null) "--logging-format \"${toString cfg.logging-format}\""} \
            ${optionalString (cfg.machine-id-file != null) "--machine-id-file \"${toString cfg.machine-id-file}\""} \
            ${optionalString (cfg.masquerade-all != null) "--masquerade-all"} \
            ${optionalString (cfg.master != null) "--master \"${toString cfg.master}\""} \
            ${optionalString (cfg.metrics-bind-address != null) "--metrics-bind-address \"${toString cfg.metrics-bind-address}\""} \
            ${optionalString (cfg.nodeport-addresses != null) "--nodeport-addresses \"${concatStringsSep "," cfg.nodeport-addresses}\""} \
            ${optionalString (cfg.oom-score-adj != null) "--oom-score-adj \"${toString cfg.oom-score-adj}\""} \
            ${optionalString (cfg.pod-bridge-interface != null) "--pod-bridge-interface \"${toString cfg.pod-bridge-interface}\""} \
            ${optionalString (cfg.pod-interface-name-prefix != null) "--pod-interface-name-prefix \"${toString cfg.pod-interface-name-prefix}\""} \
            ${optionalString (cfg.profiling != null) "--profiling \"${boolToString cfg.profiling}\""} \
            ${optionalString (cfg.proxy-mode != null) "--proxy-mode \"${toString cfg.proxy-mode}\""} \
            ${optionalString (cfg.proxy-port-range != null) "--proxy-port-range \"${toString cfg.proxy-port-range}\""} \
            ${optionalString (cfg.show-hidden-metrics-for-version != null) "--show-hidden-metrics-for-version \"${toString cfg.show-hidden-metrics-for-version}\""} \
            ${optionalString (cfg.v != null) "--v \"${toString cfg.v}\""} \
            ${optionalString (cfg.vmodule != null) "--vmodule \"${concatStringsSep "," cfg.vmodule}\""}
        '';
        Restart = "on-failure";
        RestartSec = 5;
      };
      unitConfig = {
        StartLimitIntervalSec = 0;
      };
    };
  };
}
