# Kubernetes

Pods, deployments, logs and warnings of a cluster; scale and restart
workloads. Conduit talks to the API server directly, so no `kubectl` or
kubeconfig is needed on the machine running it.

**Setup.** Create a service account with only the rights you want Conduit to
have, and a token for it:

```sh
kubectl create serviceaccount conduit -n default
kubectl create clusterrolebinding conduit-view --clusterrole=view --serviceaccount=default:conduit
kubectl create token conduit -n default --duration=8760h
```

Store the token in the vault and add an instance with the API server address
(`kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'`),
the token reference and the cluster's CA certificate (PEM, inline or as a
`secret://` reference). The `view` role covers the read actions; scaling,
restarting and deleting pods also need `patch` on `deployments` and
`deployments/scale` and `delete` on `pods` (the `edit` role, or a narrower
role of your own).

| Action | Risk | Notes |
| --- | --- | --- |
| `namespaces` | read | |
| `pods` | read | Phase, ready containers, restarts, node, age and why a container is waiting (e.g. `CrashLoopBackOff`). Optional label `selector`. |
| `deployments` | read | Desired, ready, updated and available replicas |
| `logs` | read | `pod`, optional `container`, `tailLines` (default 200, at most 5000), `since` (e.g. `15m`), `previous` for a crashed container |
| `events` | read | Warning events, newest first (at most 100); `all` includes normal events |
| `scale` | write | Preview shows the old and new replica count. Undo scales back. |
| `restart` | destructive | A rolling restart, like `kubectl rollout restart`. Preview available. |
| `delete_pod` | destructive | The preview says which controller owns the pod, so you can see whether it comes back. |

Every action takes an optional `namespace`; without it the instance's
default namespace is used. Names are checked against Kubernetes' naming
rules before any request is made.

**Security.** The token is resolved from the vault for each request and
never shown. Leave `insecureSkipVerify` off: without certificate checks,
anyone on the network path can read the token. Give the service account the
smallest role that does what you need; Conduit's policies decide what agents
may do, and the cluster's RBAC is the second fence.
