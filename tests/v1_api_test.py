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

import datetime
import json
import os
import subprocess
import time
import urllib2

server_url = "http://localhost:8080"
primary_test_email = "e2eshare.test@gmail.com"

app_id = "pgp"
key_format = 2
key = str.replace("""mFIEAAAAABMIKoZIzj0DAQcCAwRNDJYwov/h0/XUVEALnyLf4PfMP3bGpJO
DLtkkIXSAZaC7rKurE6F/h3r8Uq9TMiZO4lvYBLUYRyMQDfYidAaKtBk8ZTJlc2hhcmUudGVzdEBnbWF
pbC5jb20+iI0EExMIAD//AAAABQJVjCNs/wAAAAIbA/8AAAACiwn/AAAABZUICQoL/wAAAAOWAQL/AAA
AAp4B/wAAAAmQSyDbFK+ygeMAAEaEAQDdUlASPe+J7E7BZWMI+1lpfvHQsH1Tv6ubkkn9akJ91QD/eG3
H3UIVH6KV/fXWft7pEva5i6Jsx6ikO63kVWFbYaK4VgQAAAAAEggqhkjOPQMBBwIDBFpSLVgW2RSga/C
USF3a2Wnv0kdeybCXdB/G1K+v2LaTb6bNtNu39DlDtf8XDm5u5kfLQcL5LFhDoDe5aGP02iUDAQgHiG0
EGBMIAB//AAAABYJVjCNs/wAAAAKbDP8AAAAJkEsg2xSvsoHjAACzNwEAtQEtl9jKzlGYeng4YskWACy
Dnba5o/rGwcoFjRf1BiwBAPFn0SrS6WSUpU0+B+8k+PXDpFKMZHZYo/E6qtVrpdYT""", "\n", "")
key_id = "470f80552bffbd9b74fb399b4b20db14afb281e3"

create_key_request = {
    "signed_key": {
        "key": {
            "app_id": app_id,
            "format": key_format,
            "key": key
        }
    }
}

update_key_request = {
    "signed_key": {
        "key": {
            "app_id": app_id,
            "format": key_format,
            "key": key,
            "creation_time": datetime.datetime.utcnow().isoformat("T") + "Z"
        }
    }
}


def main():
  # Start the server.
  null_output = open(os.devnull, "w")
  subprocess.Popen(["./svr"], stdout=null_output, stderr=subprocess.STDOUT)
  # Wait until the server starts.
  time.sleep(1)

  # Start testing.
  CreateKey()
  GetUser(False)
  UpdateKey()
  GetUser(False)
  DeleteKey()
  GetUser(True)

  # Kill the server.
  subprocess.Popen(["killall", "svr"])


def GetUser(empty):
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
    # Key list includes signed_key.
    assert "signed_keys" in dict_response["key_list"]
    # Signed key includes a single key.
    assert len(dict_response["key_list"]["signed_keys"]) == 1
    assert "key" in dict_response["key_list"]["signed_keys"][0]
    # App ID as expected.
    assert "app_id" in dict_response["key_list"]["signed_keys"][0]["key"]
    assert dict_response["key_list"]["signed_keys"][0]["key"][
        "app_id"] == app_id
    # Format as expected.
    assert "format" in dict_response["key_list"]["signed_keys"][0]["key"]
    assert dict_response["key_list"]["signed_keys"][0]["key"][
        "format"] == key_format
    # Actual key as expected.
    assert "key" in dict_response["key_list"]["signed_keys"][0]["key"]
    assert dict_response["key_list"]["signed_keys"][0]["key"]["key"] == key
    # Key ID as expected.
    assert "key_id" in dict_response["key_list"]["signed_keys"][0]
    assert dict_response["key_list"]["signed_keys"][0]["key_id"] == key_id

  end_time = time.time()

  if empty:
    print "ok\tget empty user\t%.2fs" % (end_time - start_time)
  else:
    print "ok\tget non-empty user\t%.2fs" % (end_time - start_time)


def CreateKey():
  start_time = time.time()

  create_api_path = "/v1/users/" + primary_test_email + "/keys"
  request = urllib2.Request(server_url + create_api_path)
  request.add_header("Content-Type", "application/json")
  response = urllib2.urlopen(request, json.dumps(create_key_request))

  # HTTP response should be 200.
  assert response.getcode() == 200

  # Ensure that returned JSON is as expected.
  body = response.read()
  dict_response = json.loads(body)
  # Response includes a key.
  assert "key" in dict_response
  # App ID as expected.
  assert "app_id" in dict_response["key"]
  assert dict_response["key"]["app_id"] == app_id
  # Format as expected.
  assert "format" in dict_response["key"]
  assert dict_response["key"]["format"] == key_format
  # Actual key as expected.
  assert "key" in dict_response["key"]
  assert dict_response["key"]["key"] == key
  # Key ID as expected.
  assert "key_id" in dict_response
  assert dict_response["key_id"] == key_id

  end_time = time.time()

  print "ok\tcreate key\t%.2fs" % (end_time - start_time)


def UpdateKey():
  start_time = time.time()

  update_api_path = "/v1/users/" + primary_test_email + "/keys/" + key_id
  request = urllib2.Request(server_url + update_api_path)
  request.add_header("Content-Type", "application/json")
  request.get_method = lambda: "PUT"
  response = urllib2.urlopen(request, json.dumps(update_key_request))

  # HTTP response should be 200.
  assert response.getcode() == 200

  # Ensure that returned JSON is as expected.
  body = response.read()
  dict_response = json.loads(body)
  # Response includes a key.
  assert "key" in dict_response
  # App ID as expected.
  assert "app_id" in dict_response["key"]
  assert dict_response["key"]["app_id"] == app_id
  # Format as expected.
  assert "format" in dict_response["key"]
  assert dict_response["key"]["format"] == key_format
  # Actual key as expected.
  assert "key" in dict_response["key"]
  assert dict_response["key"]["key"] == key
  # Key ID as expected.
  assert "key_id" in dict_response
  assert dict_response["key_id"] == key_id

  end_time = time.time()

  print "ok\tupdate key\t%.2fs" % (end_time - start_time)


def DeleteKey():
  start_time = time.time()

  update_api_path = "/v1/users/" + primary_test_email + "/keys/" + key_id
  request = urllib2.Request(server_url + update_api_path)
  request.add_header("Content-Type", "application/json")
  request.get_method = lambda: "DELETE"
  response = urllib2.urlopen(request, json.dumps(update_key_request))

  # HTTP response should be 200.
  assert response.getcode() == 200

  # Ensure that returned JSON is as expected.
  body = response.read()
  dict_response = json.loads(body)
  # Ensure that the response is empty.
  assert not dict_response

  end_time = time.time()

  print "ok\tdelete key\t%.2fs" % (end_time - start_time)


if __name__ == "__main__":
  main()
