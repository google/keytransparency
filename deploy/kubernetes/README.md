# Usage

To spin up a minimalistic deployment of keytransparency on 
[Google Compute Engine](https://cloud.google.com/sdk/gcloud/), run the following 
command to create, upload, and run all containers:
```
./scripts/deploy.sh
```
You can observe deployed services and their pod's logs by running:
```
kubectl proxy --port=8080
```
After that you should be able to visit http://localhost:8080/ui .

## Delete mysql DB
To delete all data written to the DB you can run:
```
kubectl delete -k deploy/kubernetes/overlays/gke
```
Alternatively, you use the kubernetes HTTP user interface:
 1) Start a proxy to the kubernetes api by running `kubectl proxy --port=8080`.
 2) Find and delete the mysql pod/deployment on the 
 [user interface](http://localhost:8080/ui).

