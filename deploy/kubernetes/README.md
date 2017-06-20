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
