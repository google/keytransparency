
# Testing

## In Memory

By default the tests in `impl/spanner/...` use an [in-memory](cloud.google.com/go/spanner/spannertest) implementation of spanner that does not require any local setup.


## [Cloud Spanner Emulator](https://cloud.google.com/spanner/docs/emulator)

To test against a local docker instance of spanner, start the emulator and set environment flags. 

```
gcloud beta emulators spanner start
$(gcloud beta emulators spanner env-init)
```

View and control the emulator with the `gcloud` command:

```
gcloud config configurations create emulator
gcloud config set auth/disable_credentials true
gcloud config set project fake-proj
gcloud config set api_endpoint_overrides/spanner http://localhost:9020/
gcloud config configurations activate emulator
gcloud spanner instances list
gcloud spanner databases list --instance fake-instance
```

## [Cloud Spanner](https://cloud.google.com/spanner)

To test against an instance of spanner hosted in Google Cloud:

1. Create a Spanner instance using the [Google Cloud Console](https://console.cloud.google.com/spanner/instances/new).
1. Switch the `gcloud` configuration to `default` and authenticate.

```
unset SPANNER_EMULATOR_HOST
gcloud config configurations activate default
gcloud auth application-default login
go test ./impl/spanner/... -count 1 -args --fake_db=false --db_project=$GCP_PROJECT --db_instance=$INSTANCE_ID
```

