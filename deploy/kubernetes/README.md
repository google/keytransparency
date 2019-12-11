# Usage

To spin up a minimalistic deployment of keytransparency on 
[Google Compute Engine](https://cloud.google.com/sdk/gcloud/), run the following 
command to create, upload, and run all containers:
```
./scripts/deploy.sh
```

## Delete the deployment
To delete the deployment, run:
```
kubectl delete -k deploy/kubernetes/overlays/gke
```
