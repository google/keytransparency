// Copyright 2020 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

// Meet in the middle algorithm:
//

// NewerRevisionsToVerify returns a list of revisions to perform append-only verifications against.
// The relying party / sender is assured that if there is an entity running the
// OlderRevisionsToVerify algorithm, they will have at least on revision in
// common.
//
// `created` is the (earliest) revision a data item was found in the map.
//    It is OK to use the revision at which an item was fetched, but the algorithm will be more efficent
//    if the algorithm starts with the revision at which an item was submitted to the map.
// `verified` is the latest revision of a successfully verified consistency proof by this client.
//    When verified > created, previously verified revisions are omitted from the results.
// `current` is the current revision of the map. Selected revisions will be <= current.
func NewerRevisionsToVerify(created, current, verified int64) []int64 {
	ret := []int64{} // bⁱ = b-b mod 2ⁱ+ 2ⁱ
	if created < 1 {
		created = 1 // Revision 0 is empty.
	}
	if current < 1 {
		return []int64{} // Nothing to verify if the map is empty.
	}
	if created > current {
		created = current
	}
	for r := created; r <= current && r > 0; r = next(r) {
		// check = created + 2ⁱ - created mod 2ⁱ
		if r <= verified {
			continue
		}
		if r > current {
			break
		}
		ret = append(ret, r)
	}
	return ret
}

// OlderRevisionsToVerify returns a list of revisions to perform append-only verifications against.
// The provider / data owner / data verifier periodically verifies that their data history contained in
// the current map revision contains all the data committed to in select previous revisions.
// The provider is assured that any relying party has verified that they data
// they have fetched is represented in at least one of the selected revisions.
//
// `current` is the current revision of the map.
// `verified` is the latest verified revision for this particular data item.
//
// TODO: Consier limiting the max period between checks to the expected value
// of other party lifetimes -- the maximum amount of time this algorithm can
// tollerate the other party being offline at an unknown point in the past.
// Currently this algorithm expects the relying party to keep it's memory and
// be online at least once every `current = 2ⁱ` revisions. See Tests.
func OlderRevisionsToVerify(current, verified int64) []int64 {
	ret := []int64{} // aⁱ = a - a mod 2ⁱ
	if current < 1 {
		return []int64{}
	}
	for r := current; r >= 0; r = prev(r) {
		if r <= verified {
			break
		}
		ret = append(ret, r)
	}
	return ret
}

// prev return r-2ˡᵉᵛᵉˡ⁽ʳ⁾
func prev(rev int64) int64 { return rev & (rev - 1) }

// next return r+2ˡᵉᵛᵉˡ⁽ʳ⁾
func next(rev int64) int64 { return (rev | (rev - 1)) + 1 }
