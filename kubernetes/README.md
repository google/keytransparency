# Usage

To spin up a minimalistic deployment on Google Compute Engine, run the following 
two commands:
```
../.scripts/deploy.sh
kubectl apply -f keytransparency-deployment.yml
```

**Explanation**: All neccessary docker containers will be build, uploaded to the 
project's Container Registry. Then, all containers will run in a single 
[pod](https://kubernetes.io/docs/concepts/workloads/pods/pod/). 
(See [networking in kubernetes](https://kubernetes.io/docs/concepts/cluster-administration/networking/#kubernetes-model)) 

TODO(ismail): Write an actual Readme
