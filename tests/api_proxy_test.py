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
import shutil
import subprocess
import tempfile
import time
import urllib2

server_url = "http://localhost:8080"
primary_test_email = "e2eshare.test@gmail.com"

app_id = "pgp"
complete_key = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mFIEAAAAABMIKoZIzj0DAQcCAwRNDJYwov/h0/XUVEALnyLf4PfMP3bGpJODLtkk
IXSAZaC7rKurE6F/h3r8Uq9TMiZO4lvYBLUYRyMQDfYidAaKtBk8ZTJlc2hhcmUu
dGVzdEBnbWFpbC5jb20+iI0EExMIAD//AAAABQJVjCNs/wAAAAIbA/8AAAACiwn/
AAAABZUICQoL/wAAAAOWAQL/AAAAAp4B/wAAAAmQSyDbFK+ygeMAAEaEAQDdUlAS
Pe+J7E7BZWMI+1lpfvHQsH1Tv6ubkkn9akJ91QD/eG3H3UIVH6KV/fXWft7pEva5
i6Jsx6ikO63kVWFbYaK4VgQAAAAAEggqhkjOPQMBBwIDBFpSLVgW2RSga/CUSF3a
2Wnv0kdeybCXdB/G1K+v2LaTb6bNtNu39DlDtf8XDm5u5kfLQcL5LFhDoDe5aGP0
2iUDAQgHiG0EGBMIAB//AAAABYJVjCNs/wAAAAKbDP8AAAAJkEsg2xSvsoHjAACz
NwEAtQEtl9jKzlGYeng4YskWACyDnba5o/rGwcoFjRf1BiwBAPFn0SrS6WSUpU0+
B+8k+PXDpFKMZHZYo/E6qtVrpdYT
=+kV0
-----END PGP PUBLIC KEY BLOCK-----"""

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
# and (2) marshling the results into base64 which is JSON representation of
# bytes.
# primary_user_profile = {
#     "key_list": {
#         "app_id": app_id,
#         "key": key
#     }
# }
primary_user_profile = str.replace("""Es0DCgNwZ3ASxQOYUgQAAAAAEwgqhkjOPQMBBwIDBE
0MljCi/+HT9dRUQAufIt/g98w/dsakk4Mu2SQhdIBloLusq6sToX+HevxSr1MyJk7iW9gEtRhHIxAN9i
J0Boq0GTxlMmVzaGFyZS50ZXN0QGdtYWlsLmNvbT6IjQQTEwgAP/8AAAAFAlWMI2z/AAAAAhsD/wAAAA
KLCf8AAAAFlQgJCgv/AAAAA5YBAv8AAAACngH/AAAACZBLINsUr7KB4wAARoQBAN1SUBI974nsTsFlYw
j7WWl+8dCwfVO/q5uSSf1qQn3VAP94bcfdQhUfopX99dZ+3ukS9rmLomzHqKQ7reRVYVthorhWBAAAAA
ASCCqGSM49AwEHAgMEWlItWBbZFKBr8JRIXdrZae/SR17JsJd0H8bUr6/YtpNvps2027f0OUO1/xcObm
7mR8tBwvksWEOgN7loY/TaJQMBCAeIbQQYEwgAH/8AAAAFglWMI2z/AAAAApsM/wAAAAmQSyDbFK+yge
MAALM3AQC1AS2X2MrOUZh6eDhiyRYALIOdtrmj+sbBygWNF/UGLAEA8WfRKtLpZJSlTT4H7yT49cOkUo
xkdlij8Tqq1Wul1hM=""", "\n", "")
# This signed entry update is generated from (1) marshalling the following
# signed entry update and (2) marshaling the results into base64 which is JSON
# representation of bytes.
# signed_entry_update = {
#     "entry": {
#         "index": <primary_user_index>
#     }
# }
primary_signed_entry_update = "GiIiIFMz0U4iG5mVzIxhtdSvFKHGiUiWBf7Zb/8yUORcWxsN"

update_user_request = {
    "user_id": primary_test_email,
    "update": {
        "signed_update": primary_signed_entry_update,
        "profile": primary_user_profile,
    }
}


def main():
  # Create a tmp directory.
  test_server_db_path = tempfile.mkdtemp(prefix="db-server")
  # Start the server.
  null_output = open(os.devnull, "w")
  subprocess.Popen(
      ["./srv", "-server-db-path", test_server_db_path],
      stdout=null_output,
      stderr=subprocess.STDOUT)
  # Wait until the server starts.
  time.sleep(1)

  # Start testing.
  GetEntryV1(True)
  HkpGet(True)
  GetEntryV2(True)
  # UpdateEntryV2()
  # GetEntryV1(False)
  # HkpGet(False)
  # GetEntryV2(False)

  # Kill the server.
  subprocess.Popen(["killall", "srv"])
  # Remove database tmp directory.
  shutil.rmtree(test_server_db_path)


def GetEntryV1(empty):
  start_time = time.time()

  get_api_url = "/v1/users/" + primary_test_email
  request = urllib2.Request(server_url + get_api_url)
  try:
    response = urllib2.urlopen(request)

    # HTTP response should be 200.
    assert response.getcode() == 200

    # Empty should be false here.
    assert not empty

    # Ensure that what is returned is as expected.
    body = response.read()
    dict_response = json.loads(body)
    # Response includes key list.
    assert "keys" in dict_response
    # Key list includes a single key.
    assert len(dict_response["keys"]) == 1
    assert app_id in dict_response["keys"]
    # Actual key as expected.
    assert dict_response["keys"][app_id] == key
  except urllib2.HTTPError as err:
    assert empty and err.code == 404

  end_time = time.time()

  if empty:
    print "ok\t v1: get empty user\t%.2fs" % (end_time - start_time)
  else:
    print "ok\t v1: get non-empty user\t%.2fs" % (end_time - start_time)


def HkpGet(empty):
  start_time = time.time()

  get_api_url = "/v1/hkp/lookup?op=get&search=" + primary_test_email
  request = urllib2.Request(server_url + get_api_url)
  try:
    response = urllib2.urlopen(request)

    # Empty should be false here.
    assert not empty

    # HTTP response should be 200.
    assert response.getcode() == 200

    # Ensure that what is returned is as expected.
    body = response.read()
    assert body == complete_key
  except urllib2.HTTPError as err:
    assert empty and err.code == 404

  end_time = time.time()

  if empty:
    print "ok\thkp: get empty key\t%.2fs" % (end_time - start_time)
  else:
    print "ok\thkp: get non-empty key\t%.2fs" % (end_time - start_time)


def GetEntryV2(empty):
  start_time = time.time()

  get_api_url = "/v2/users/" + primary_test_email
  request = urllib2.Request(server_url + get_api_url)
  try:
    response = urllib2.urlopen(request)

    # HTTP response should be 200.
    assert response.getcode() == 200

    # Ensure that what is returned is as expected.
    body = response.read()
    dict_response = json.loads(body)
    if empty:
      # Response includes index_signature
      assert "index" in dict_response
    else:
      # Response includes profile.
      assert "profile" in dict_response
      assert dict_response["profile"] == primary_user_profile
  except urllib2.HTTPError as err:
    assert empty and err.code == 404

  end_time = time.time()

  if empty:
    print "ok\t v2: get empty user\t%.2fs" % (end_time - start_time)
  else:
    print "ok\t v2: get non-empty user\t%.2fs" % (end_time - start_time)


def UpdateEntryV2():
  start_time = time.time()

  update_api_path = "/v2/users/" + primary_test_email
  request = urllib2.Request(server_url + update_api_path)
  request.add_header("Content-Type", "application/json")
  request.get_method = "PUT"
  response = urllib2.urlopen(request, json.dumps(update_user_request))

  # HTTP response should be 200.
  assert response.getcode() == 200

  # Ensure that returned JSON is as expected.
  body = response.read()
  # Body of update response is empty
  assert body == empty_protobuf_json

  end_time = time.time()

  print "ok\t v2: update key\t%.2fs" % (end_time - start_time)


if __name__ == "__main__":
  main()
