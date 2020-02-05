# NGINX Configs

Installing baremetal NGINX requires running the following commands according to the [directions](https://kubernetes.github.io/ingress-nginx/deploy/) on the nginx site.

```
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.28.0/deploy/static/mandatory.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.28.0/deploy/static/provider/cloud-generic.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.28.0/deploy/static/provider/baremetal/service-nodeport.yaml
```

The directories below contain the contents of these three configs
1. Split out into their component yaml files.
2. Added `kustomization.yaml` files tying them together.
3. Removed conflicting resources.

The kustomize dependency graph looks like so:
```
overlays\local -> overlays\local\ingress-nginx\baremetal
overlays\local\ingress-nginx\baremetal -> overlays\local\ingress-nginx\cloudgeneric
overlays\local\ingress-nginx\cloudgeneric -> overlays\local\ingress-nginx\static
```
