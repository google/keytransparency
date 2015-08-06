# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import subprocess
import time
import urllib2

server_url = "http://localhost:8080"
primary_test_email = "e2eshare.test@gmail.com"

app_id = "pgp"
key = str.replace("""mFIEAAAAABMIKoZIzj0DAQcCAwRNDJYwov/h0/XUVEALnyLf4PfMP3bGpJO
DLtkkIXSAZaC7rKurE6F/h3r8Uq9TMiZO4lvYBLUYRyMQDfYidAaKtBk8ZTJlc2hhcmUudGVzdEBnbWF
pbC5jb20+iI0EExMIAD//AAAABQJVjCNs/wAAAAIbA/8AAAACiwn/AAAABZUICQoL/wAAAAOWAQL/AAA
AAp4B/wAAAAmQSyDbFK+ygeMAAEaEAQDdUlASPe+J7E7BZWMI+1lpfvHQsH1Tv6ubkkn9akJ91QD/eG3
H3UIVH6KV/fXWft7pEva5i6Jsx6ikO63kVWFbYaK4VgQAAAAAEggqhkjOPQMBBwIDBFpSLVgW2RSga/C
USF3a2Wnv0kdeybCXdB/G1K+v2LaTb6bNtNu39DlDtf8XDm5u5kfLQcL5LFhDoDe5aGP02iUDAQgHiG0
EGBMIAB//AAAABYJVjCNs/wAAAAKbDP8AAAAJkEsg2xSvsoHjAACzNwEAtQEtl9jKzlGYeng4YskWACy
Dnba5o/rGwcoFjRf1BiwBAPFn0SrS6WSUpU0+B+8k+PXDpFKMZHZYo/E6qtVrpdYT""", "\n", "")
key_id = "470f80552bffbd9b74fb399b4b20db14afb281e3"
# Empty protobuf in marshaled to JSON is '{}\n'
empty_protobuf_json = "{}\n"

# This profile is genrated from (1) marshaling the following profile protobuf
# and (2) marshling the results into JSON.
# primary_user_profile = {
#     "key_list": {
#         "app_id": app_id,
#         "key": key
#     }
# }
primary_user_profile = str.replace("""Es0DEsUDmFIEAAAAABMIKoZIzj0DAQcCAwRNDJYwov
/h0/XUVEALnyLf4PfMP3bGpJODLtkkIXSAZaC7rKurE6F/h3r8Uq9TMiZO4lvYBLUYRyMQDfYidAaKtB
k8ZTJlc2hhcmUudGVzdEBnbWFpbC5jb20+iI0EExMIAD//AAAABQJVjCNs/wAAAAIbA/8AAAACiwn/AA
AABZUICQoL/wAAAAOWAQL/AAAAAp4B/wAAAAmQSyDbFK+ygeMAAEaEAQDdUlASPe+J7E7BZWMI+1lpfv
HQsH1Tv6ubkkn9akJ91QD/eG3H3UIVH6KV/fXWft7pEva5i6Jsx6ikO63kVWFbYaK4VgQAAAAAEggqhk
jOPQMBBwIDBFpSLVgW2RSga/CUSF3a2Wnv0kdeybCXdB/G1K+v2LaTb6bNtNu39DlDtf8XDm5u5kfLQc
L5LFhDoDe5aGP02iUDAQgHiG0EGBMIAB//AAAABYJVjCNs/wAAAAKbDP8AAAAJkEsg2xSvsoHjAACzNw
EAtQEtl9jKzlGYeng4YskWACyDnba5o/rGwcoFjRf1BiwBAPFn0SrS6WSUpU0+B+8k+PXDpFKMZHZYo/
E6qtVrpdYTGgNwZ3A=""", "\n", "")

update_user_request = {
    "user_id": primary_test_email,
    "update": {
        "profile": primary_user_profile
    }
}


def main():
  # Start the server.
  null_output = open(os.devnull, "w")
  subprocess.Popen(["./svr"], stdout=null_output, stderr=subprocess.STDOUT)
  # Wait until the server starts.
  time.sleep(1)

  # Start testing.
  GetUserV1(True)
  GetUserV2(True)
  UpdateUserV2()
  GetUserV1(False)
  GetUserV2(False)

  # Kill the server.
  subprocess.Popen(["killall", "svr"])


def GetUserV1(empty):
  start_time = time.time()

  get_api_url = "/v1/users/" + primary_test_email
  request = urllib2.Request(server_url + get_api_url)
  response = urllib2.urlopen(request)

  # HTTP response should be 200.
  assert response.getcode() == 200

  # Ensure that what is returned is as expected.
  body = response.read()
  if empty:
    assert not body
  else:
    dict_response = json.loads(body)
    # Response includes key list.
    assert "key_list" in dict_response
    # Key list includes a single key.
    assert len(dict_response["key_list"]) == 1
    assert "key" in dict_response["key_list"][0]
    # App ID as expected.
    assert "app_id" in dict_response["key_list"][0]
    assert dict_response["key_list"][0]["app_id"] == app_id
    # Actual key as expected.
    assert "key" in dict_response["key_list"][0]
    assert dict_response["key_list"][0]["key"] == key

  end_time = time.time()

  if empty:
    print "ok\tv1: get empty user\t%.2fs" % (end_time - start_time)
  else:
    print "ok\tv1: get non-empty user\t%.2fs" % (end_time - start_time)


def GetUserV2(empty):
  start_time = time.time()

  get_api_url = "/v2/users/" + primary_test_email
  request = urllib2.Request(server_url + get_api_url)
  response = urllib2.urlopen(request)

  # HTTP response should be 200.
  assert response.getcode() == 200

  # Ensure that what is returned is as expected.
  body = response.read()
  if empty:
    assert not body
  else:
    dict_response = json.loads(body)
    # Response includes profile.
    assert "profile" in dict_response
    assert dict_response["profile"] == primary_user_profile

  end_time = time.time()

  if empty:
    print "ok\tv2: get empty user\t%.2fs" % (end_time - start_time)
  else:
    print "ok\tv2: get non-empty user\t%.2fs" % (end_time - start_time)


def UpdateUserV2():
  start_time = time.time()

  update_api_path = "/v2/users/" + primary_test_email
  request = urllib2.Request(server_url + update_api_path)
  request.add_header("Content-Type", "application/json")
  request.get_method = lambda: "PUT"
  response = urllib2.urlopen(request, json.dumps(update_user_request))

  # HTTP response should be 200.
  assert response.getcode() == 200

  # Ensure that returned JSON is as expected.
  body = response.read()
  # Body of update response is empty
  assert body == empty_protobuf_json

  end_time = time.time()

  print "ok\tv2: update key\t%.2fs" % (end_time - start_time)


if __name__ == "__main__":
  main()
