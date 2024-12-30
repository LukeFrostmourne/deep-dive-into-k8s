# Mimir Overview


# Architecture


[Grafana Mimir architecture |  Grafana Mimir documentation](https://grafana.com/docs/mimir/latest/get-started/about-grafana-mimir-architecture/)

# Components

we are using [***microservices mode***](https://grafana.com/docs/mimir/latest/references/architecture/deployment-modes/#microservices-mode)

<aside>
💡 all components are in the same AZ because cross zone traffic is expensive

</aside>

## Gateway

### deployment

A nginx deployment to receive traffic for Mimir as reverse proxy  

```jsx
╰─ k get deploy mimir-gateway
NAME            READY   UP-TO-DATE   AVAILABLE   AGE
mimir-gateway   2/2     2            2           2d23h
```

k8s service is used as upstream,  the `query_frontend` one is used as datasource in grafana and the `distributor` is used by prometheus remote write.

```bash
...
location = /api/v1/push {
  set $distributor mimir-distributor-headless.monitoring.svc.cluster.local;
  proxy_pass      http://$distributor:8080$request_uri;
}

location /prometheus/config/v1/rules {
    set $ruler mimir-ruler.monitoring.svc.cluster.local;
    proxy_pass      http://$ruler:8080$request_uri;
}
...
location /prometheus {
   set $query_frontend mimir-query-frontend.monitoring.svc.cluster.local;
   proxy_pass      http://$query_frontend:8080$request_uri;
}
```

mimir supports multi-tenant with http header `X-Scope-OrgID` , the default one is used when it’s empty which also is the directory name in s3.

```bash
# Ensure that X-Scope-OrgID is always present, default to the no_auth_tenant for backwards compatibility when multi-tenancy was turned off.
map $http_x_scope_orgid $ensured_x_scope_orgid {
   default $http_x_scope_orgid;
   "" "default_tenant";
}

server {
  listen 8080;
  listen [::]:8080;
	proxy_set_header X-Scope-OrgID $ensured_x_scope_orgid;
	...
}
```

### service

Internal traffic (traffic from the clusters in Tokyo region ) is using cilium global service(clustermesh).

```jsx
╰─ k get svc mimir-gateway
NAME            TYPE        CLUSTER-IP             EXTERNAL-IP   PORT(S)           AGE
mimir-gateway   ClusterIP   fd94:a19f:c88e::8c0c   <none>        80/TCP,8080/TCP   3d
```

If the prometheus cluster is in the same with mimir, then the cilium global service is used as remote write URL to save cost, also all the related components should be deployed in the same AZ to avoid cross AZ traffic.

### ingress

External traffic (different env or different region) is using AWS LB.

```jsx
╰─ k get ingress mimir-gateway
NAME            CLASS    HOSTS                     ADDRESS                                                                                 PORTS   AGE
mimir-gateway   <none>   mimir.dev.smartnews.net     80      3d
```

## Writes Components

### [Distributor](https://grafana.com/docs/mimir/latest/references/architecture/components/distributor/)

Gateway forwards the remote write request from prometheus to distributor

```bash
location = /api/v1/push {
  set $distributor mimir-distributor-headless.monitoring.svc.cluster.local;
  proxy_pass      http://$distributor:8080$request_uri;
}
```

Distributor itself is a stateless deployment

```jsx
╰─ k get deploy mimir-distributor
NAME                READY   UP-TO-DATE   AVAILABLE   AGE
mimir-distributor   3/3     3            3           134m
```

- sharding
    
    > For each incoming series, the distributor computes a hash using the metric name, labels, and tenant ID. The computed hash is called a *token*. The distributor looks up the token in the hash ring to determine which ingesters to write a series to.
    > 
    
    It’s the default behavior, we’re just using the default settings.
    
- HA tracker
    
    > The distributor includes an HA tracker. When the HA tracker is enabled, the distributor deduplicates incoming series from Prometheus HA pairs.
    > 
    
    This is required because we have 2 replicas per prometheus shard
    
    ```jsx
    prometheus-kube-prometheus-stack-prometheus-0     2/2     Running   0          23h
    prometheus-kube-prometheus-stack-prometheus-1     2/2     Running   0          8h
    ```
    
    consul is deployed for [HA tracker](https://grafana.com/docs/mimir/latest/configure/configure-high-availability-deduplication/#how-to-configure-grafana-mimir), distributor is using consul k8s svc as endpoint.
    
    ```bash
    ╰─ k get sts consul-consul-server
    
    NAME                   READY   AGE
    consul-consul-server   3/3     121m
    
    ╰─ k get svc consul-consul-server
    NAME                   TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)                                                                            AGE
    consul-consul-server   ClusterIP   None         <none>        8500/TCP,8502/TCP,8301/TCP,8301/UDP,8302/TCP,8302/UDP,8300/TCP,8600/TCP,8600/UDP   122m
    ```
    
    To make it work, [extra settings](https://grafana.com/docs/mimir/latest/configure/configure-high-availability-deduplication/#distributor-high-availability-ha-tracker%20accept_ha_samples:%20true,) are required.
    
    - in mimir
        
        ```yaml
        ha_cluster_label: 'cortex_ha_id',
        ha_replica_label: 'replica',
        ```
        
    - in prometheus
        
        ```yaml
         externalLabels:
            cortex_ha_id: xxx
        ```
        

distributor provides a UI to show status, but we have to use port-forward to access from local `kubectl port-forward svc/mimir-distributor 8080`


In IPv6 cluster, must enable the ipv6 option in ring settings(same for [all components](https://grafana.com/docs/mimir/latest/references/architecture/hash-ring/#components-that-use-a-hash-ring) using hash ring).

```yaml
ring:
	instance_enable_ipv6: true
```

### [Ingester](https://grafana.com/docs/mimir/latest/references/architecture/components/ingester/)

A statefulset with pv which is used to store WAL.

```bash
╰─ k get sts mimir-ingester
NAME             READY   AGE
mimir-ingester   3/3     44h
```

> the ingesters batch and compress samples in-memory and periodically upload them to the long-term storage, Writes to the Mimir cluster are successful if a majority of ingesters received the data. With the default replication factor of 3, this means 2 out of 3 writes to ingesters must succeed.
> 

The default `replication_factor` is 3 which means we need at least 3 replicas for this statefulset. Ingester writes data to disk and periodically uploaded (by default every two hours) to the long-term storage([S3 bucket](https://grafana.com/docs/mimir/latest/get-started/about-grafana-mimir-architecture/#long-term-storage).

```yaml
 	# Number of ingesters that each time series is replicated to. This option
  # needs be set on ingesters, distributors, queriers and rulers when running in
  # microservices mode.
  # CLI flag: -ingester.ring.replication-factor
  [replication_factor: <int> | default = 3]
```


## Reads Components

### [Query-frontend](https://grafana.com/docs/mimir/latest/references/architecture/components/query-frontend/)

frontend is used by grafana to query metrics

```bash
location /prometheus {
   set $query_frontend mimir-query-frontend.monitoring.svc.cluster.local;
   proxy_pass      http://$query_frontend:8080$request_uri;
}
```

- caching
    
    A memcached statefulset is deployed as results cache.
    
    ```bash
    ╰─ k get sts mimir-results-cache
    NAME                  READY   AGE
    mimir-results-cache   3/3     7h23m
    ```
    
- [query sharding](https://grafana.com/docs/mimir/latest/references/architecture/query-sharding/)
    
    > Each shardable portion of a query is split into `-query-frontend.query-sharding-total-shards` partial queries. If a query has multiple inner portions that can be sharded, each portion is sharded `-query-frontend.query-sharding-total-shards` times
    > 
    
    ```yaml
    frontend:
       parallelize_shardable_queries: true
       query_sharding_target_series_per_shard: 5000
    	 query_sharding_total_shards: 30
    limits:
       max_query_parallelism: 1200
       query_sharding_max_sharded_queries: 256
       split_instant_queries_by_interval: 24h
    ```
    
    over time query is divided by 24h which means there will be 30 queries when query the last 30d.  `query_sharding_max_sharded_queries` limits the max number of partial queries to 256.
    

### [Query-scheduler](https://grafana.com/docs/mimir/latest/references/architecture/components/query-scheduler/)

> When you use the query-scheduler, the queue is moved from the query-frontend to the query-scheduler, and the query-frontend can be scaled to any number of replicas.
> 

There’s no specific config for query scheduler, but the replicas must be smaller than `querier.max-concurrent`

### [Querier](https://grafana.com/docs/mimir/latest/references/architecture/components/querier/)

> The querier uses the [store-gateway](https://grafana.com/docs/mimir/latest/references/architecture/components/store-gateway/) component to query the [long-term storage](https://grafana.com/docs/mimir/latest/get-started/about-grafana-mimir-architecture/#long-term-storage) and the [ingester](https://grafana.com/docs/mimir/latest/references/architecture/components/ingester/) component to query recently written data.
> 

`max_concurrent`  is increased to 100(at least larger than `query_sharding_total_shards`), but shouldn’t be too large since we want to use autoscaling.

```yaml
querier:
	 # The number of workers running in each querier process. 
	 # This setting limits the maximum number of concurrent queries in each querier.
   max_concurrent: 100
```

### [Ruler](https://grafana.com/docs/mimir/latest/references/architecture/components/ruler/)

> The ruler is an optional component that evaluates PromQL expressions defined in recording and alerting rules.
> 

```bash
╰─ k get deploy mimir-ruler
NAME          READY   UP-TO-DATE   AVAILABLE   AGE
mimir-ruler   3/3     3            3           5d20h
```

we’re using the [remote mode](https://grafana.com/docs/mimir/latest/references/architecture/components/ruler/#remote)

```yaml
ruler:
  alertmanager_url: dns+http://kube-prometheus-stack-alertmanager.monitoring.svc.cluster.local:9093
  query_frontend:
    address: dns:mimir-query-frontend.monitoring.svc.cluster.local:9095
```


### [Store-gateway](https://grafana.com/docs/mimir/latest/references/architecture/components/store-gateway/)

> On the read path, the [querier](https://grafana.com/docs/mimir/latest/references/architecture/components/querier/) and the [ruler](https://grafana.com/docs/mimir/latest/references/architecture/components/ruler/) use the store-gateway when handling the query, whether the query comes from a user or from when a rule is being evaluated.
> 

```bash
╰─ k get sts mimir-store-gateway
NAME                  READY   AGE
mimir-store-gateway   3/3     6d1h
```


## Storage Components

### [S3 bucket](https://grafana.com/docs/mimir/latest/get-started/about-grafana-mimir-architecture/#long-term-storage)


```yaml
blocks_storage:
  backend: s3
  s3:
    bucket_name: xxx
    endpoint: s3.ap-northeast-1.amazonaws.com
limits:
	compactor_blocks_retention_period: '1y'
```

One folder is created per tenant inside the bucket


### Cache

all caches are using [memcached](https://memcached.org/).

- [results cache](https://grafana.com/docs/mimir/latest/references/architecture/components/query-frontend/#caching)
    
    it’s used by query-frontend.
    
    ```bash
    ╰─ k get sts mimir-results-cache
    NAME                  READY   AGE
    mimir-results-cache   3/3     3d3h
    ```
    
- [metadata cache](https://grafana.com/docs/mimir/latest/references/architecture/components/querier/#metadata-cache)
    
    it’s used by store-gateway and querier. 
    
    ```bash
    ╰─ k get sts mimir-metadata-cache
    NAME                   READY   AGE
    mimir-metadata-cache   3/3     3d6h
    ```
    
- [chunks cache](https://grafana.com/docs/mimir/latest/references/architecture/components/store-gateway/#chunks-cache)
    
    it’s used by store-gateway.
    
    ```bash
    ╰─ k get sts mimir-chunks-cache
    NAME                 READY   AGE
    mimir-chunks-cache   3/3     6d2h
    ```
    
- [index cache](https://grafana.com/docs/mimir/latest/references/architecture/components/store-gateway/#index-cache)
    
    it’s used by store-gateway.
    
    ```bash
    ╰─ k get sts mimir-index-cache
    NAME                READY   AGE
    mimir-index-cache   3/3     6d2h
    ```
    

### [Compactor](https://grafana.com/docs/mimir/latest/references/architecture/components/compactor/)

```bash
╰─ k get sts mimir-compactor
NAME              READY   AGE
mimir-compactor   3/3     6d2h
```

### [Overrides-exporter](https://grafana.com/docs/mimir/latest/references/architecture/components/overrides-exporter/)

It’s used to set global limits per tenant which is required for [runtime config](https://grafana.com/docs/mimir/latest/configure/about-runtime-configuration/)

```bash
╰─ k get deploy mimir-overrides-exporter
NAME                       READY   UP-TO-DATE   AVAILABLE   AGE
mimir-overrides-exporter   1/1     1            1           6d2h
```

# Multi-tenant Support

Mimir supports [multi-tenancy](https://grafana.com/docs/mimir/latest/manage/secure/authentication-and-authorization/)  by default, it just looks at the http header `X-Scope-OrgID` which is the tenant ID

## Config

- Write
    
    Set the header in Prometheus [remotewrite](https://github.com/prometheus-operator/prometheus-operator/blob/main/Documentation/api.md#remotewritespec) spec.
    
- Read
    
    Set the header in Grafana datasource
    
    ```yaml
    	- name: Cortex
        type: prometheus
        url: "http://cortex-query-frontend-headless.cortex:8080/prometheus"
        isDefault: true
        jsonData:
          httpHeaderName1: 'X-Scope-OrgID'
        secureJsonData:
          httpHeaderValue1: 'default_tenant'
    ```
    

# Usage Control

## Scrape interval

The default scrape interval is 1m which can be changed by the setting of servicemonitor.

Setting longer interval will reduce metrics count.

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kube-state-metrics
  namespace: monitoring
spec:
  endpoints:
  - honorLabels: true
    interval: 120s
    port: http
    scrapeTimeout: 110s
```

# Known issues

## Too many unhealthy ingester in the ring

### Issue

All ingester pods are in a hash ring, if multiple pods are terminated the entire ring becomes unhealthy even the left pods are able to handle all requests.

### Solution

Deployed a workaround to remove unhealthy pods periodically.

The script just run every 5s to remove unhealthy pods by mimir API.

```bash
 "while true; do\n  echo \"start cleanup\"\n  which curl > /dev/null 2>&1\n
    \ if [ $? -eq 1 ]; then\n    apk add curl\n  fi\n  which jq > /dev/null 2>&1\n
    \ if [ $? -eq 1 ]; then\n    apk add jq\n  fi\n\n  curl -H \"Accept: application/json\"
    http://mimir-distributor:8080/ingester/ring | \n    jq \".shards[] | select(.state==\\\"UNHEALTHY\\\" or .state==\\\"LEAVING\\\")
    | .id\" |\n    sed 's|\"||g' |\n    xargs -I{} curl -d \"forget={}\"  -H \"Accept:
    application/json\" http://mimir-distributor:8080/ingester/ring\n  \n  sleep 5\n
    \ echo \"cleanup done\"\ndone\ntrue\n"
```

<aside>
💡 Once the terminated pod is started, it will register automatically again.

</aside>

## Distributors keep crashing

### Issue

Normally distributors don’t consume much resources, but when some distributors are down there will be a huge memory usage increase for the left ones in a short time. And if some got OOMKilled, all distributors will keep crashing due to OOMKill eventually. 

### Solution

- Make distributors small and distributed on different nodes as much as possible.
- Set a big memory limit.