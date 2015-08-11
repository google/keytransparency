// Copyright 2015 Google Inc. All Rights Reserved.
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

package keyserver

import (
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/armor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	eccGood = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG v1.52

mFIEVM1AEBMIKoZIzj0DAQcCAwQVe/FaAtok6VxbFeeg1SZHHisVY2ZiJoZaJ5ux
6r5hmbRlQJ8iAXy+quxu9dpXOHJjZj5tQHRTy56VmtWHpj2/tA48ZWNjQGdvb2Qu
Y29tPohxBBMTCAAZBQJVURYQAhsDAosJBZUICQoLA5YBAgKeAQAKCRC5Ip6TPGi+
pgbKAP413nzxyB7e5ZiuZRbcXPSms25FMI3r2vX5Epu8REJLvAEAksShtjV0LFNb
R6p5uZ50n7qlMW5nBQNKL0jzTn9I7VK4VgRUzUAQEggqhkjOPQMBBwIDBMDb3RVJ
H1SZTc30kxe4QX2DUINFLwiEPCVrlBTt/TBUYHD/Xe3jn3AD+0kzEWOYrNxx2jc4
/KOTgqhvC7qKOrUDAQgHiGEEGBMIAAkFglTNQBACmwwACgkQuSKekzxovqbANQEA
tT/8MbdPOmAot1d4onKRMcFSn8vHqyBIxxKnU0tDndsA/AgBaBv4ztqKGtjSktUY
u1OEhTJSZbDxEXNE80i98CLR
=XKzW
-----END PGP PUBLIC KEY BLOCK-----`
	eccBadSignSubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG v1.52

mFIEVM1LdBMIKoZIzj0DAQcCAwSZSvSM7buSkEW1Cg6mN9+Kka1snctn40qRFrks
5XTIZGCsnvbw1mpShNpkj/CDMjAx9pyQ+8mHk7caaT5BaEhqtBI8ZWNjQGJhZC5z
aWduLmNvbT6IcQQTEwgAGQUCVVEhdAKbAwKLCQWVCAkKCwOWAQICngEACgkQJQdq
vNet5BCxvwD+Ntz1MogBwAvFfGzR9rx7P+HsC4ulEjUfFx90mwHeVrYBAP3iaSO6
X1bpAWBhRyy3cYszUZpKqpLdXTMczT5AMBl0uFIEVM1LdBMIKoZIzj0DAQcCAwQP
SLGlgh63mRfzP5hKEGB4IMNGtw5mmyK7eeMIsVcNcUC98GTVc6q89wM+8f7Gn55g
X43aeJuu9Y8uv9psYjZYiGEEGBMIAAkFglTNS3QCmwIACgkQJQdqvNet5BCRKgD+
Ka84ZQh9B7zOcD3l68b7kwiIB082L/lHuLYYw0Czdh8BALOQIS/Xrd4S68MChiAF
erqR+IlGx6vkfKYfCaDXA+rT
=mALU
-----END PGP PUBLIC KEY BLOCK-----`
	eccBadSig = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG v1.52

mFIEVM1AvxMIKoZIzj0DAQcCAwSnSMW7PD7lH4gnGkk3YJv9K/uxM98ZMMLSctfk
z/uQfMP7x60mwN731LOtc2vwZEoLrmwNkxQUWGZSFC6iRPrDtBc8ZWNjQGJhZC5z
aWduYXR1cmUuY29tPohwBBMTAgAZBQJVURa/AhsDAosJBZUICQoLA5YBAgKeAQAK
CRAJJN1sE+gf1ZboAPiKf9SbyCQTxfTjxtLY04Tog3WUARhd1jr4+oqcZZMgAQC7
5p0gOcgT3ZldICQAm2m1U8DvrIzF5dWQcFbscJapcbhWBFTNQL8SCCqGSM49AwEH
AgMEv9qYIv/VtwciJYVhafHnWhOeJGexmgg9CgJFVDrr/a7HxpvTmqEA57n07EGb
5xqyLp6XrBKzC5bH04dJoD+3YgMBCAeIYQQYEwIACQWCVM1AvwKbDAAKCRAJJN1s
E+gf1UWiAQDMMP7+GfQ0M9rbRSnvBWD48ZB/LlN88Xkq9G12VpZilwD/Q1xl7pmV
/KzMmnvyUVGSnOIR4ntnjbAKW2ijfaTIRbA=
=JKQW
-----END PGP PUBLIC KEY BLOCK-----`
	eccMulti = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG v1.52

mFIEVM1KXhMIKoZIzj0DAQcCAwQ/+k4tmTFhtunVX+Tlv+XiWUwxgMtn1qId0vX3
yiqoJSDO/LGgAHaJOqKT1gsxgwXLkVWNhSKM1KZahjQ68MTdtBA8ZWNjMUBtdWx0
aS5jb20+iHEEExMIABkFAlVRIF4CmwMCiwkFlQgJCgsDlgECAp4BAAoJEMOQlx/m
FJYc0L0A/2w5bHJAW4GRQLXsaQiZ6tsiXyZjyoVJMPyv7u/LabtFAP9Y5LIPFk5t
ZAtor24zlp3OryURdIU5kReLAoidjasP2bQQPGVjYzJAbXVsdGkuY29tPohxBBMT
CAAZBQJVUSBeApsDAosJBZUICQoLA5YBAgKeAQAKCRDDkJcf5hSWHF4dAQCoo2wK
+NGA05+t5PRbp+ii3QbV/sjaCFIyjVA5pWMKGAEAxmrLPy7om1+MP0/v3eNssNh/
vGgt6LCL0KCszsKRr5m4VgRUzUpeEggqhkjOPQMBBwIDBLV10JnP9ZxKJEruWRJU
WAMbIF+FcLUcmx1pTDAiMqNDP7VqToKaMCMAa3iCn/Q21fncnxe0aF0g1yy/tZ+O
RvgDAQgHiGEEGBMIAAkFglTNSl4CmwwACgkQw5CXH+YUlhzBcQD8C5dRAOcA/aOZ
fZMGNPFIlijFcfiwBysG3W7tzES/UAMA/1dxQyyq3d/MYoT3w/Nu9/lmg9iMne9x
F/luamhWCqAY
=p4cU
-----END PGP PUBLIC KEY BLOCK-----`
	eccMultiSubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG v1.52

mFIEVM1MvhMIKoZIzj0DAQcCAwSjbMysh64lzZUEnQNLdT3tYPX+efRBKtTBqhZc
/NRHczsqlSJa7FL6zCpF8U/HmuJ5gN6LojuiP09MWVPWeiIHtBY8ZWNjQG11bHRp
LnN1YmtleS5jb20+iHEEExMIABkFAlVRIr4CmwMCiwkFlQgJCgsDlgECAp4BAAoJ
ELkHxMQaQVO4AuwA/j1js75dxMj+1jOHr8/j+yzLGKXl5Yz5Lww1hmdaqvU4APwI
FFs/ApcXfRSJCxfy8FvkXM5EvXJvtQfqTsF/HKSMV7hWBFTNTL4SCCqGSM49AwEH
AgME5HbiZL3Kv6apsmxg4yHvZwAYKWO6fg1PMUbuzt+gRIgjsEO+iJkCftpxEfTA
lrbCKGJ6y9ypOt57kg6vG+c4SgMBCAeIYQQYEwgACQWCVM1MvgKbDAAKCRC5B8TE
GkFTuPtHAQCFrEa54LBxib/BvtjRNh4nKFEogcmj5y61iBSjUw6irgD/cgYjPBC8
zrH+92dgcG1aa1ZxUb4wWptnTZB/xd4mw264VgRUzUy+EggqhkjOPQMBBwIDBDJj
CZYWjRQ5O4f3QIdXft7nUTjmySJ05b58hmOa4v3i1zZSD9iNtQKToBJOlcVreXVx
llkmU3+XVON8zQ/1a2cDAQgHiGEEGBMIAAkFglTNTL4CmwwACgkQuQfExBpBU7iO
DwD8CKUVJjguhXgbn/8uSXIHbBSaHU/9+WV4KAUn3Ze2tSEA/1WXa5z+kT9Mqk8p
gjrwE2WEi+gRm85CFQU3MAC/54+B
=H7dI
-----END PGP PUBLIC KEY BLOCK-----`
	expiredUID = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFN76T4BCACA04Pjpjl4i2+5tM/o5p3nFDuYga8ApFgBJHaQkYExYktGqi5j
a9q4DTDCt9j+wJorzBryJuDYA6y32WHY5TPFShBArSZC4rx/ObDFUBRgSP85cQDP
kcAXVmBHH1X3DtB5apgPtrehY3U8O3Ii/yQlTCfXxUVvpVZMYt+c+7+ZAPIsttlt
oHKDw1P8ZOHruU7lzMrmOaALdcyPphHzoF0jaxnmX5lpRua4TIqUz7CwiSBZdZr5
GP3lVL9x6z4MSVpdotkMxlK7ucyoISNDG1Bd/MUN7salkiFynMvkX8UC//KbIgqa
9WI66j9R3L007RAz+AyLuL3O0zsMqJguTH9FABEBAAG0C2V4cGlyZWQta2V5iQEu
BBMBAgAYAhsDAgsHAhUIAh4BBYJTe+k+BYMAAVGAAAoJEAtEj/PvQNBSEWUH/3E8
JmeWH4KzKDWOaufQCEaZR6pwTcINPOM4vzP098zmcaYy6KeavQe1KqfNo90JE2XX
l9VvwA3DKDDMZ1T1RdwOZtLs3ItnUEGMUaDHx2teQyRzUAtTEGRe4jKE5H0D2AH3
/ZWDSohKFp/qmZvTZ5/s27At9omj/Hys/2H4SoSZT8TJfo9qC5dtziSHroPqF3xx
d6irZf900+Psf6reIusENz6n030pvSiT18pmCP8JDcJlbcSiZN2ixHQkCiM8Jnrf
JFZ0/MqAxP1+dqN9U8XD1sKeq7iZWJjOTHOqMb+Tmek5/nQfzd22WRam5mzB5qnX
Fz5qykc9wJLpO3vsJrG0CGdvb2Qta2V5iQE4BBMBAgAiBQJT/8IEAhsvBgsJCAcD
AgYVCAIJCgsEFgIDAQIeAQIXgAAKCRALRI/z70DQUp0IB/4m1G60KnB1bF1xg6pv
8CPcDZMQKWHsKbAdA1bLJjNjfXQPBDXcDAS9yfyqKV5cy7Jkz4oOkeYTpy9iKqIn
Nq97JChuHFYuxfzs0EQAxK/0hpE2tNBNgTGM1QkNOVMiMwD3lXT+Y8efo0hgQ1wp
qzL1GLnjrRkaxIYd2Q4NYLcFJxe2vET5ZUilS/Gejd5IQtlnOoPdP9hewPagl9qh
UmrxEV9n1w+hDGiEbX9d+QIeSoZPWJkY6FptI0E2npIOB3LF3UQ83NdhHG+YbVja
5GazLV2afoD//WageNM2vQ0IlRKOHIf8JbJMX6Qhf33dq2tjNaziNBs4gjf79ZU4
aDYh
=gHUD
-----END PGP PUBLIC KEY BLOCK-----`
	revokedUID = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1
Comment: Use "gpg --dearmor" for unpacking

mI0EVCnIwAEEAMOAK0ih0zqegWYOKd5MnQaqiR7aFuvUOPmD8usq1eaL7o2LfzkI
sUDHVPuQWqgExvbV0BhB3pqpWc1POPIj9RqaBuVbDRh3/h9nXb4D+ZieAmLG0vrf
nGhTO4v78Wrr4b37ggJVoPQp2vRQH2alUjMvOmoM33Yr+22hIkzHIosbABEBAAG0
DXNob3VsZC1yZXZva2WIqAQTAQIAEgIbAwILBwIVCAIeAQWCVCnIwAAKCRBQ8guz
j1S7C++fBACYMFGYCyFkCL+oNP8MZsC4NqdHjb4jHVSKD1T7vpNs+J5nsJABcNz1
4U5LiVteQWK+ommchV9LdKNl40axhnXsfAixz7UTA2ArypHaPAP8xv/hAP0wXcn5
5jHxSk4M4rAUH2y+IU2+r8YZNvLCZNKO9kppfSuYDyw5pbs8bMv5BIicBDABAgAG
BYJUpwdAAAoJEFDyC7OPVLsLsoQEAIQlekZqSr/AGg7D9gIQx/l6xXGY7732slQa
cLPZr8Szht2hc31dOICB8erMo2HdsitXOYB5rNloY33FB48NQGOEU/e8ephpgzni
WSztbBX5SVrNgi5mrZlAX98KYhOMb1XvB3lacZZY7sqhmjjdM5m6hyPjYGoxDUyE
PGvnNOpXiKgEEwECABICGwMCCwcCFQgCHgEFglSgb8AACgkQUPILs49UuwugDQQA
lEpsMAtyHW/p2sxiFplHMtOsAsJ1rsRNTKUzGLNCQWNsRAgZwY7J+g2DcIiPxf17
8bpPlESkYIXgzeyABfJqzSsgQqXvyXCoG0XbZ9Y2az/F2BitLAdph3IDcGv2cPch
rm0+J/vPh6eS9Uh8EY6k+iJI0MkX7KbwvwWTGPiTpbO0BGdvb2SIqAQTAQIAEgIb
AwILBwIVCAIeAQWCVK2ewAAKCRBQ8guzj1S7C80zA/9XK4F390WiFWj3Atb8lRQB
fOowa+GGd61is0ohXZNk7E4p5US1ozqOIcrggVKs4k4NckTQnpylIPn5csWEeIJK
HE7RIOSyiEU+ksoJDoGuZqgo0V6C5lGeDqUg1u/bcQcwkE6f/QahD/C9uBGou5SY
VKxljMH6lfwqdGT6xNa5qQ==
=KIyw
-----END PGP PUBLIC KEY BLOCK-----`
	expiredSubkey = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFN7748BCADlXXWbsunER3lvTHEElkViIq25VGtakZoaLv3q97VYZ0kIW+qQ
06tSu3CzK+JN0tcYBoejry2f/k6mmIW8IB9OAtkTyOLLyC5cL4hyHe49hqFP5wzI
KPaRphO0qAI7WZyxvGjLkVF7mVSoj8Uu6nTSnEtCg3/axxv2Wtrq5aOD9EoikZMP
wZQpqLM0Tw7yCgckOgDHlTd8LV1Ay1bIYWjj3UmdwrTpAq/noKMMj2zXeiXWjUlv
6J664dICjYmv/NcEqzFpz3R9w7ndRhWZtqhLydc/8zI/IY8q/ebsTi+kZaSW5GIg
U5lcZXE/JpyeMPQKqWol5qpUmYWNJqLqAiklABEBAAG0DmV4cGlyZWQtc3Via2V5
iQEoBBMBAgASBQJT/8WQAhsDAgsHAhUIAh4BAAoJEGzOR/QRT3xrWZwH/2SjkXGc
EinBoVNivrsLGOdrUua/aTY6PDy1J4rIypdDkTtgywvt+KKwL6BjraHhRmVEGU26
oXdrKHXHnuP4MWFUHwsAdPkA6C0cPxeJxrORL/OQ5IPx17LLe2cwVVPBmM8NHbmz
pLuKAFU7Qf0N79RoOfqolfM1wdUDQMvB18YriVGpBLHfujzcnzMfsISFNquRcb+V
Uo5iLJ0Vk/JlkYSop+hGHFb+OWSXx0SC6yXuVSnC635457y+GHbhGy7Y50JCKO4J
UKQctDDZm6AIInBOhnTEGc6RbMSYQhvi7Z/6WJnvxf6abbVKIujHXJq+An2dGVIQ
R7Nlxif2N8MY+XW5AQ0EU3vvjwEIAMUUsMpyABuPhQm3Qu76bg1/P2Wqf8de/oo1
k0grjy177jaGAdViLosvHYdp46BVT/z4NDS1ZVHb2fcuC/0YzVuevHC5IA4fiSUr
QrjMJVB5eB8+Y2fc2matvrZyBmcicUHV/LCQ6de4QFHBKs3Qj9HBIFMLMUMsEVH5
g08uFCUpSgPV2MyB2eAZARZ4Z4O5bLWNpafELNdJ2JgTuHjYH5SkeF5kR5m0KMKw
BizcqxmtzMBipq8DNi8zgkwY2E7ngrtMFLUQSvTVNxQnWGlm/osL7GCXv+Vtuee1
eu/h6Jsf7FCObY9SQs7xxCVWnQC3PNbAfpbrk1bU4nMt9+DBDHUAEQEAAYkBJQQY
AQIADwIbDAUCU3vvjwUDAAFRgAAKCRBszkf0EU98a2SyB/42odA+rA8vw9xiQRQg
bJMW/lmeSBmHI5MmomgtRrYtizDPx//8FsWBi8oPF1sw2vBWZEkqEeVBhhLoqxEk
c2XcjQnOqrYDZ1Cn6W8v+IoKePQNaltJpgcJu/vyUXtf2b6rKVCsAOmJVGzsM+m3
g3iuMSXKi3dWTs0S7ezusfhSqtBZEouRvsnlVUM/ZHhWY8fFpz4UF7ARH9mS2Aqc
hx5JIGRQP5teVX0unJCgdLICk2CmqENqMeg7MyMu1/0KoW+FMgBuD9X9HsqLHD1s
l79KGLk9OEwlEPU9k0ejqC6zUDXp+F01zTTBtrkqI0fgOE9hsrc3IMZLmWLgUKvy
59L+
=9yM7
-----END PGP PUBLIC KEY BLOCK-----`
	missingCrossSignature = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFMYynYBCACVOZ3/e8Bm2b9KH9QyIlHGo/i1bnkpqsgXj8tpJ2MIUOnXMMAY
ztW7kKFLCmgVdLIC0vSoLA4yhaLcMojznh/2CcUglZeb6Ao8Gtelr//Rd5DRfPpG
zqcfUo+m+eO1co2Orabw0tZDfGpg5p3AYl0hmxhUyYSc/xUq93xL1UJzBFgYXY54
QsM8dgeQgFseSk/YvdP5SMx1ev+eraUyiiUtWzWrWC1TdyRa5p4UZg6Rkoppf+WJ
QrW6BWrhAtqATHc8ozV7uJjeONjUEq24roRc/OFZdmQQGK6yrzKnnbA6MdHhqpdo
9kWDcXYb7pSE63Lc+OBa5X2GUVvXJLS/3nrtABEBAAG0F2ludmFsaWQtc2lnbmlu
Zy1zdWJrZXlziQEoBBMBAgASBQJTnKB5AhsBAgsHAhUIAh4BAAoJEO3UDQUIHpI/
dN4H/idX4FQ1LIZCnpHS/oxoWQWfpRgdKAEM0qCqjMgiipJeEwSQbqjTCynuh5/R
JlODDz85ABR06aoF4l5ebGLQWFCYifPnJZ/Yf5OYcMGtb7dIbqxWVFL9iLMO/oDL
ioI3dotjPui5e+2hI9pVH1UHB/bZ/GvMGo6Zg0XxLPolKQODMVjpjLAQ0YJ3spew
RAmOGre6tIvbDsMBnm8qREt7a07cBJ6XK7xjxYaZHQBiHVxyEWDa6gyANONx8duW
/fhQ/zDTnyVM/ik6VO0Ty9BhPpcEYLFwh5c1ilFari1ta3e6qKo6ZGa9YMk/REhu
yBHd9nTkI+0CiQUmbckUiVjDKKe5AQ0EUxjKdgEIAJcXQeP+NmuciE99YcJoffxv
2gVLU4ZXBNHEaP0mgaJ1+tmMD089vUQAcyGRvw8jfsNsVZQIOAuRxY94aHQhIRHR
bUzBN28ofo/AJJtfx62C15xt6fDKRV6HXYqAiygrHIpEoRLyiN69iScUsjIJeyFL
C8wa72e8pSL6dkHoaV1N9ZH/xmrJ+k0vsgkQaAh9CzYufncDxcwkoP+aOlGtX1gP
WwWoIbz0JwLEMPHBWvDDXQcQPQTYQyj+LGC9U6f9VZHN25E94subM1MjuT9OhN9Y
MLfWaaIc5WyhLFyQKW2Upofn9wSFi8ubyBnv640Dfd0rVmaWv7LNTZpoZ/GbJAMA
EQEAAYkBHwQYAQIACQUCU5ygeQIbAgAKCRDt1A0FCB6SP0zCB/sEzaVR38vpx+OQ
MMynCBJrakiqDmUZv9xtplY7zsHSQjpd6xGflbU2n+iX99Q+nav0ETQZifNUEd4N
1ljDGQejcTyKD6Pkg6wBL3x9/RJye7Zszazm4+toJXZ8xJ3800+BtaPoI39akYJm
+ijzbskvN0v/j5GOFJwQO0pPRAFtdHqRs9Kf4YanxhedB4dIUblzlIJuKsxFit6N
lgGRblagG3Vv2eBszbxzPbJjHCgVLR3RmrVezKOsZjr/2i7X+xLWIR0uD3IN1qOW
CXQxLBizEEmSNVNxsp7KPGTLnqO3bPtqFirxS9PJLIMPTPLNBY7ZYuPNTMqVIUWF
4artDmrG
=7FfJ
-----END PGP PUBLIC KEY BLOCK-----`
	invalidCrossSignature = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBFMYynYBCACVOZ3/e8Bm2b9KH9QyIlHGo/i1bnkpqsgXj8tpJ2MIUOnXMMAY
ztW7kKFLCmgVdLIC0vSoLA4yhaLcMojznh/2CcUglZeb6Ao8Gtelr//Rd5DRfPpG
zqcfUo+m+eO1co2Orabw0tZDfGpg5p3AYl0hmxhUyYSc/xUq93xL1UJzBFgYXY54
QsM8dgeQgFseSk/YvdP5SMx1ev+eraUyiiUtWzWrWC1TdyRa5p4UZg6Rkoppf+WJ
QrW6BWrhAtqATHc8ozV7uJjeONjUEq24roRc/OFZdmQQGK6yrzKnnbA6MdHhqpdo
9kWDcXYb7pSE63Lc+OBa5X2GUVvXJLS/3nrtABEBAAG0F2ludmFsaWQtc2lnbmlu
Zy1zdWJrZXlziQEoBBMBAgASBQJTnKB5AhsBAgsHAhUIAh4BAAoJEO3UDQUIHpI/
dN4H/idX4FQ1LIZCnpHS/oxoWQWfpRgdKAEM0qCqjMgiipJeEwSQbqjTCynuh5/R
JlODDz85ABR06aoF4l5ebGLQWFCYifPnJZ/Yf5OYcMGtb7dIbqxWVFL9iLMO/oDL
ioI3dotjPui5e+2hI9pVH1UHB/bZ/GvMGo6Zg0XxLPolKQODMVjpjLAQ0YJ3spew
RAmOGre6tIvbDsMBnm8qREt7a07cBJ6XK7xjxYaZHQBiHVxyEWDa6gyANONx8duW
/fhQ/zDTnyVM/ik6VO0Ty9BhPpcEYLFwh5c1ilFari1ta3e6qKo6ZGa9YMk/REhu
yBHd9nTkI+0CiQUmbckUiVjDKKe5AQ0EUxjKdgEIAIINDqlj7X6jYKc6DjwrOkjQ
UIRWbQQar0LwmNilehmt70g5DCL1SYm9q4LcgJJ2Nhxj0/5qqsYib50OSWMcKeEe
iRXpXzv1ObpcQtI5ithp0gR53YPXBib80t3bUzomQ5UyZqAAHzMp3BKC54/vUrSK
FeRaxDzNLrCeyI00+LHNUtwghAqHvdNcsIf8VRumK8oTm3RmDh0TyjASWYbrt9c8
R1Um3zuoACOVy+mEIgIzsfHq0u7dwYwJB5+KeM7ZLx+HGIYdUYzHuUE1sLwVoELh
+SHIGHI1HDicOjzqgajShuIjj5hZTyQySVprrsLKiXS6NEwHAP20+XjayJ/R3tEA
EQEAAYkCPgQYAQIBKAUCU5ygeQIbAsBdIAQZAQIABgUCU5ygeQAKCRCpVlnFZmhO
52RJB/9uD1MSa0wjY6tHOIgquZcP3bHBvHmrHNMw9HR2wRCMO91ZkhrpdS3ZHtgb
u3/55etj0FdvDo1tb8P8FGSVtO5Vcwf5APM8sbbqoi8L951Q3i7qt847lfhu6sMl
w0LWFvPTOLHrliZHItPRjOltS1WAWfr2jUYhsU9ytaDAJmvf9DujxEOsN5G1YJep
54JCKVCkM/y585Zcnn+yxk/XwqoNQ0/iJUT9qRrZWvoeasxhl1PQcwihCwss44A+
YXaAt3hbk+6LEQuZoYS73yR3WHj+42tfm7YxRGeubXfgCEz/brETEWXMh4pe0vCL
bfWrmfSPq2rDegYcAybxRQz0lF8PAAoJEO3UDQUIHpI/exkH/0vQfdHA8g/N4T6E
i6b1CUVBAkvtdJpCATZjWPhXmShOw62gkDw306vHPilL4SCvEEi4KzG72zkp6VsB
DSRcpxCwT4mHue+duiy53/aRMtSJ+vDfiV1Vhq+3sWAck/yUtfDU9/u4eFaiNok1
8/Gd7reyuZt5CiJnpdPpjCwelK21l2w7sHAnJF55ITXdOxI8oG3BRKufz0z5lyDY
s2tXYmhhQIggdgelN8LbcMhWs/PBbtUr6uZlNJG2lW1yscD4aI529VjwJlCeo745
U7pO4eF05VViUJ2mmfoivL3tkhoTUWhx8xs8xCUcCg8DoEoSIhxtOmoTPR22Z9BL
6LCg2mg=
=Dhm4
-----END PGP PUBLIC KEY BLOCK-----`
	invalidSubpacketLength = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFPmr2EBCACn2FimzdgSY7K1CG8M7hdz3/nQ7hHVM2ulG/WtEe6ZdlHG1mo7
i4jo2JzlAdLhnF/mZwuMJ72Wy+QUJ5Um38d6ly95RmlXPkNDz01Mb+f9YF3u36TV
o7NTIzcgK6T9kVp6ksr3IktoW3rKKFUsTkKnUuCCbl843x0uqGu3fv7JEC/AVPUt
hPNYFCttDr07p00cNbrBr8+QJXBDx//SZtCYmjrtpFP0HmARvRknx1tAun0+S9AG
AsOJLdXu8ZJPWHqwNb38J69uVk5W7dpGe0ZQdx9n9EfYXDv/wWT+8/c7YGLqCtIf
qMXW+PKdgAo5xqL4S+rqfGZHlT5y8fyIhY45ABEBAAHNCFRoZSDwnYyGiQEoBBMB
AgASAhsBAgsHAhUIAh4BBQJT5q9hAAq/EDjUhTTltozLhBYIAJYP08yoeKWk5cj0
B9Y51PEzII8fGrJDeoltJ+O1iPBteiA0Es3Q3XOXtkjqPFMzDpgjEpqAj+fSE5VC
AsGP63ozSg4zOCDF8k++/iX+t5A3i+xGTZmknisccjVdcx/1nVFBK8dEy6WE+ir9
f74GEqERKGvgLyFXlS6dXzs5J1gSY0pOq5NxYkHauz/9QIKSoxMxDad0AJbVegBX
ESFbpA5UETgojzviA6Q/jz6c0N1cHTEQD2MnTsk8xRSnRsYG6AL96f4i6cwpdV2I
CW4s/mR2ZILuKKsS6WxY8Q8AVeKMW4cXWJZO/cMwok9Gk8oZORdWr8AkVxOLfvf/
aCOr+QE=
=d3vQ
-----END PGP PUBLIC KEY BLOCK-----`
)

func TestGoodKey(t *testing.T) {
	tests := []struct {
		label  string
		key    string
		userID string
		want   codes.Code
	}{
		{"eccGood", eccGood, "<ecc@good.com>", codes.OK},
	}
	for i, test := range tests {
		block, err := armor.Decode(strings.NewReader(test.key))
		if err != nil {
			t.Errorf("Test[%v]: test %v: invalid armor", i, test.label)
		} else if _, err := validatePGP(test.userID, block.Body); err != nil {
			t.Errorf("Test[%v]: test %s: validatePGP(%q, _)) = _, %v; want nil", i, test.label, test.userID, err)
		}
	}
}

func TestInvalidKeys(t *testing.T) {
	tests := []struct {
		label  string
		key    string
		userID string
		want   codes.Code
	}{
		{"eccBadSignSubkey", eccBadSignSubkey, "<ecc@bad.sign.com>", codes.Unknown},
		{"eccBadSig", eccBadSig, "<ecc@bad.signature.com>", codes.InvalidArgument},
		{"eccMulti", eccMulti, "", codes.InvalidArgument},
		{"eccMutliSubKey", eccMultiSubkey, "<ecc@multi.subkey.com>", codes.InvalidArgument},
		{"expiredUID", expiredUID, "", codes.InvalidArgument},
		{"revokedUID", revokedUID, "", codes.InvalidArgument},
		{"expiredSubkey", expiredSubkey, "expired-subkey", codes.InvalidArgument},
		{"missingCrossSignature", missingCrossSignature, "invalid-signing-subkeys", codes.Unknown},
		{"invalidCrossSignature", invalidCrossSignature, "invalid-signing-subkeys", codes.Unknown},
		{"invalidSubpacketLen", invalidSubpacketLength, "", codes.Unknown},
	}
	for i, test := range tests {
		block, err := armor.Decode(strings.NewReader(test.key))
		if err != nil {
			t.Errorf("Test[%v]: test %v: invalid armor", i, test.label)
		} else if _, err := validatePGP(test.userID, block.Body); err == nil {
			t.Errorf("Test[%v]: test %v: validatePGP(%q, _) = _, nil, want %v", i, test.label, test.userID, test.want)
		} else if got := grpc.Code(err); got != test.want {
			t.Errorf("Test[%v]: test %s: validatePGP(%q, _)) = _, %v; want %v", i, test.label, test.userID, got, test.want)
		}
	}
}
