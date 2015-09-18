End-to-End Key Server HTTP APIs
====================

# Introduction

This document describes the End-to-End Key Server HTTP APIs, their signature, the generated HTTP responses, and the returned errors.

# V1 APIs

### GetEntry

* Method: `GET`.
* URL: `/v1/user/{user_id}`.
* Query String:
  * `epoch`: the value of this parameter will *always* be replaced with `math.MaxUint64` by the proxy server. This indicates that the requested entry belongs to the current serving epoch.
  * `app_id`: allows application-based filtering of keys of the returned profile.
* Body: empty.
* Response: JSON body containing `Profile` proto.
* Requirements: input parameters are not required, anything missing is handled by the key server. The following behavior is currently implemented by the server:
  * missing `app_id`: do not apply application-based filtering of keys.
* Errors:
  * `http.StatusNotFound`: if:
    * epoch does not exist,
    * user is not found,
    * or database entry is not found.
  * `http.StatusBadRequest`: if:
    * index length is not valid.
  * `http.StatusInternalServerError`: if:
    * index cannot be processed,
    * or unmarshalling results in any error.

### HkpLookup

* Method: `GET`.
* URL: `/v1/hkp/lookup`.
* Query String:
  * `op`: specifies the requested operation, only `get` is currently implemented.
  * `search`: contains the user’s email address.
  * `options`: specifies HKP lookup option, only `mr` is currently implemented.
* Body: empty.
* Response: JSON body containing the requested key.
* Requirements: input parameters are not required, anything missing is handled by the key server. The following behavior is currently implemented by the server:
  * missing or unsupported `op`: results in `http.StatusNotImplemented` error.
  * missing `search`: results in `http.StatusNotFound` error.
  * missing `options`: no effect.
* Errors:
  * `http.StatusNotFound`: if:
    * user is not found,
    * or database entry is not found.
  * `http.StatusBadRequest`: if:
    * index length is not valid.
  * `http.StatusInternalServerError`: if:
    * index cannot be processed,
    * or unmarshalling results in any error.
  * `http.StatusNotImplemented`: if:
    * operation is not supported,
    * search parameter is specifying a key ID instead of email,
    * or multiple keys are found in the user profile matching `pgp` application ID.

# V2 APIs

### GetEntry

* Method: `GET`.
* URL: `/v2/user/{user_id}`.
* Query String:
  * `epoch`: contains the epoch in which the user profile is requested. Use `math.MaxUint64` to indicate the current serving epoch.
  * `app_id`: allows filtering the profile based on a specific application ID.
* Body: empty.
* Response: JSON body containing `GetEntryResponse` proto.
* Requirements: input parameters are not required, anything missing is handled by the key server. The following behavior is currently implemented by the server:
  * missing `epoch`: use the current epoch.
  * missing `app_id`: do not apply application-based filtering of keys.
* Errors:
  * `http.StatusNotFound`: if:
    * database entry is not found.
  * `http.StatusBadRequest`: if:
    * index length is not valid.
  * `http.StatusInternalServerError`: if:
    * index cannot be processed,
    * or unmarshalling results in any error.

### UpdateEntry

* Method: `PUT`.
* URL: `/v2/user/{user_id}`.
* Query String: none.
* Body: JSON body containing `UpdateEntryRequest` proto.
* Response: JSON body containing `UpdateEntryResponse` proto.
* Requirements: all fields of the input `UpdateEntryRequest` proto are not checked for existence by the HTTP proxy. Any requirement is enforced by the key server. The following behavior is implemented by the server:
  * short or missing `profile_nonce`: results in `http.StatusBadRequest` error.
* Errors:
  * `http.StatusBadRequest`: if:
    * profile nonce is not valid, e.g. shorter than the required minimum.

### ListEntryHistory

* Method: `GET`.
* URL: `/v2/user/{user_id}/history`.
* Query String:
  * `start_epoch`: specifies the start epoch of the history.
  * `page_size`: specifies the maximum number of entries to return.
* Body: empty.
* Response: JSON body containing `ListEntryHistoryResponse` proto.
* Requirements: input parameters are not required, anything missing is handled by the key server. The following behavior is currently implemented by the server:
  * missing `start_epoch`: use the first epoch assuming that the whole history is being requested.
  * missing `page_size`: do not upper bound the number of returned entries.
* Errors:
  * `http.StatusBadRequest`: if:
    * start epoch does not exist, or
    * index length is not valid.
  * `http.StatusNotFound`: if:
    * database entry is not found.
  * `http.StatusInternalServerError`: if:
    * index cannot be processed,
    * or unmarshalling results in any error.

### ListSEH

* Method: `GET`.
* URL: `/v2/seh`.
* Query String:
  * `start_epoch`: specifies the start epoch of the SEH list.
  * `page_size`: specifies the maximum number of entries to return.
* Body: empty.
* Response: JSON body containing `ListSEHResponse` proto.
* Requirements: input parameters are not required, anything missing is handled by the key server. The following behavior is currently implemented by the server:
  * missing `start_epoch`: use the first epoch assuming that the whole SEH list is being requested.
  * missing `page_size`: do not upper bound the number of returned entries.
* Errors: TBD.

### ListUpdate

* Method: `GET`.
* URL: `/v2/update`.
* Query String:
  * `start_epoch`: specifies the start epoch of the history.
  * `page_size`: specifies the maximum number of entries to return.
* Body: empty.
* Response: JSON body containing `ListUpdateResponse` proto.
* Requirements: input parameters are not required, anything missing is handled by the key server. The following behavior is currently implemented by the server:
  * missing `start_epoch`: use the first epoch assuming that the whole list of updates is being requested.
  * missing `page_size`: do not upper bound the number of returned entries.
* Errors:
  * `http.StatusBadRequest`: if:
    * start commitment timestamp does not exist.

### ListSteps

* Method: `GET`.
* URL: `/v2/step`.
* Query String:
  * `start_epoch`: specifies the start epoch of the history.
  * `page_size`: specifies the maximum number of entries to return.
* Body: empty.
* Response: JSON body containing `ListStepsResponse` proto.
* Requirements: input parameters are not required, anything missing is handled by the key server. The following behavior is currently implemented by the server:
  * missing `start_epoch`: use the first epoch assuming that the whole list of steps is being requested.
  * missing `page_size`: do not upper bound the number of returned entries.
* Errors: TBD.



