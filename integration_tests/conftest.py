import pytest
import requests
import yaml
import os
import subprocess
import time
import socket
import signal

# --- Certificates and Keys ---

CA_CERT = """-----BEGIN CERTIFICATE-----
MIIDmTCCAoGgAwIBAgIUQFlH+y76TW4GCwvGWEESfT4sTZAwDQYJKoZIhvcNAQEL
BQAwXDELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMQ0wCwYDVQQHDARVZW5v
MRQwEgYDVQQKDAtUZXN0U2VydmljZTEYMBYGA1UEAwwPTXlUZXN0U2VydmljZUNB
MB4XDTI1MDkyNDA1NDkzNFoXDTM1MDkyMjA1NDkzNFowXDELMAkGA1UEBhMCSlAx
DjAMBgNVBAgMBVRva3lvMQ0wCwYDVQQHDARVZW5vMRQwEgYDVQQKDAtUZXN0U2Vy
dmljZTEYMBYGA1UEAwwPTXlUZXN0U2VydmljZUNBMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAvqP7GuNgv5umIIXK+QqT2auq56x1oSAA+oP4Fmp+sjcO
e08QES/LlbXesVRYHHV624qInpdEKTwuENxZi0+mkm5zO09GFlQiKvas3YvN5Ecq
aWVoPWHezcXt2K+ogNU1rjPqgENvpKnWtzZPGIHiKnN0/taUR7AotxPg4wV1QVuv
EgavXqIFGBhH+Os+6HnCls3XukmMBu3YTxgB6wwYUHbXqzBQNivugXU1AFx1a7tI
GRCGEAJiJ//g1mTu8Ji2/XvN/QpkSv5GgjwDToB07ZvRNSOarODOwT37Fr87Nfy1
IpIGcmbNcpJik+LNqpyfdUALuLyXAbjjYw7OML9HqwIDAQABo1MwUTAdBgNVHQ4E
FgQUKazWF2yeXfg6aTVhYFwTyT3idPQwHwYDVR0jBBgwFoAUKazWF2yeXfg6aTVh
YFwTyT3idPQwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAa9Qc
TEzjkbIWczZ1h9xDriG8RcST0pmdTR2QMo/UeaJayNjtxp9rEuNVW8Xs7COENtPv
wfq/X3RLXh+YBYT2qC0qO1HuAoLOHchxKMEJBJo1QjVkNmJHtIq6sddzm16EmW0o
jz2dN3fp1S9PvLwKha8YOMX1R9eiwT7UHAXJjOud6xdF6T8veDvhrFKTsKxgKFkG
NoUiNw+rzOVCOuwgt1I7VcfIgA0dmjDz3RlK1nPXroZaeMKgLEAyLPh704h8vvDT
ZHgx+Nrf1b+TNgNLxpnmqFH4NWdezFSfvHHRBOY3sFvMJFU81fnk3QTZYnRwrsSD
M7eKGakIiHjPZDWOEg==
-----END CERTIFICATE-----"""

DEVICE_VERIFY_PUB_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA96yON3DXHHS7DMfe4h1W
VSyRJI/mkrKNgDmIboIGYYNcBALMblC3IRgE9gEpaGJ1Ll+At5yl4UF90iru+4Kr
/bPRRjnCUBIyBztX7TcRPlbH4zfvYHx9vJtUuckVELwzmVz5T1K6UgbXQOZv96Y6
PNcBnrc/M0zW7GWIqcktEMuSdcMlYdJ8VJYNA4sfpSQLJfZI+j964tjoVhr2JNsi
kInG6TZmNBjjPSqFtDzTLxC12ngxJQDUuN1IRqAcSchjWMFwY67voVpS39u2nFVj
rbnHFMU8bkmTF3WizL+6ZPKPU28+WrYxH4EIEhToyIhktCb9DSKUSiIGa6+KvpfN
ywIDAQAB
-----END PUBLIC KEY-----"""

DEVICE_SIGN_PRIV_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD3rI43cNccdLsM
x97iHVZVLJEkj+aSso2AOYhuggZhg1wEAsxuULchGAT2ASloYnUuX4C3nKXhQX3S
Ku77gqv9s9FGOcJQEjIHO1ftNxE+VsfjN+9gfH28m1S5yRUQvDOZXPlPUrpSBtdA
5m/3pjo81wGetz8zTNbsZYipyS0Qy5J1wyVh0nxUlg0Dix+lJAsl9kj6P3ri2OhW
GvYk2yKQicbpNmY0GOM9KoW0PNMvELXaeDElANS43UhGoBxJyGNYwXBjru+hWlLf
27acVWOtuccUxTxuSZMXdaLMv7pk8o9Tbz5atjEfgQgSFOjIiGS0Jv0NIpRKIgZr
r4q+l83LAgMBAAECggEALuPI0v82gokpBozqigWC3EJBQlpKDVjniDCcP0u3mIuN
hqbe/D2kxgutmMN0ivIk/EARdvGdyA0lnH4LW6uME06RXsm9m3ouZYcbKOplhddZ
JY/n7mzzQxtnSXsj1VTEMhNTkex4IOJxqzRVW13ppa4Q/PL1cKlqATxhyL8xHH4G
pmq8Q899T7OW7vLdysede68sjbA04fL/gaPNxPj5TpsPKvreIQRpziXDoJCalMp9
EUi0CbzpoVheahJlSi6In9byRxGauVIao+BgNh/NNYqVnj/Tp6X2YGnhN5UXYA+j
V4xMjmKFgHIFaptpUTudpyAZZnG/WQVKJDeixhscaQKBgQD9MpJw0cgLhRenwL0V
zJeMlt1OwnA4sbbmxUS67eAy31cZzUS6N2cF+2RaP0WjGSnZyxcXPA72HXnM8/dP
B5tX6ce9PJ0px7YtOnwwcjGMKqQsPALF9Uvm5FfuWlCdHaHzfUv2wUGS8ON6cJDW
qgufBrMynmtw8ZG1Wr+5MIiRgwKBgQD6alUzZrAJOwM/IYdIte3YISx4a69j0epc
Vh7Bzm3tQYF02nSFpMSKX8sQeQ5wFx4gjhGWJp3tn0xrWrsN44b0oG4zKE9QaRVJ
hCzBa/Ka+p/EsXc/kc9CSMuylJ20LtA0B5TEgYJ8QzzCA8BsRUc47+JkR3gO1N9w
jS5bPfyIGQKBgQC6f9Kv+UXBfoJDFUvxz6Zdbw6KIdxpVjWj2/BZRDgdILdWkQUr
qP1gwaBUfUB8918FRnu2qI1YqbN6zMUAWFkLM27lq80T5kABJpAtWx+13/7XekiM
qbcD1nQSZEH2yMnuwP8APa9gXcEhAeMdy1kOBPBfu6LmKXmrPLH15ZLiowKBgDgO
u7oA/+FhG43zZISLbY4XhwwCF0ZCRLOc98+s9YDKTD+rc7BDPVg4r42le+ztz+m7
xAYX6Py7z3Cs4/js+VYj3+eF25OFoqVNeHNoRewZtNBkZeyOKJaPE0KL8G3YmPU8
yTngQCSvLJfGHTpfm90MHmMSeLbhQo/AmyMD0ldpAoGBAJ9tQ3R33AYkkjCJSc/u
8X121N2+URZxuA23bMJH6OoJddtz8AFyKV36ihbVKrJ1/mcXkdZ9+WEszQaVsGsm
CvsxaZWlMj4yZoVCx7ZqrFx17AThlxCpi7rFoFZbkk+M9+RX6U8d8r39qyfqjJFp
0kaUPHgv1Qgvn5SYcebU+AQ4
-----END PRIVATE KEY-----"""

WWW_CERT = """-----BEGIN CERTIFICATE-----
MIIDlTCCAn2gAwIBAgIUOCU9p0Z5rkJksIl9EuEW5H+UFZEwDQYJKoZIhvcNAQEL
BQAwVjELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMQ0wCwYDVQQHDARVZW5v
MRIwEAYDVQQKDAlGb3JnZVNob3AxFDASBgNVBAMMC1Rlc3RGb3JnZUNBMB4XDTI2
MDIxOTAwMzMwM1oXDTM2MDIxNzAwMzMwM1owTjELMAkGA1UEBhMCSlAxDjAMBgNV
BAgMBVRva3lvMQ0wCwYDVQQHDARVZW5vMRIwEAYDVQQKDAlGb3JnZVNob3AxDDAK
BgNVBAMMA3d3dzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAPgADM6u
STz2iE4V3j0rk82k5WSE3HzZ/LTIouC37Up+PyE7fvzmQpfaO7eADvbzmZJbBkqU
zyIioT7iCcZOcokvZGyfFpfvTW0qtYlZ06xGY4bKlVcoFntj7EsjZHQER5vf9x7Y
nG/l6BhUCZ089/ZHDgVhjVsamdEgpibnMJBeJaRmfMBN1VatblOGQncVXyCWEkNO
KkWrXDxvzVtlERYcJK0BZ3fR/sftsGS1am1VJgBHRgK02rXlDceZaVGGTXJ1Ge4w
9Vb4EgJUoyhnxBe/Lqn1+sF5+fQWU9NwyOZOY+/FCU3oNHDhpf1/b58orVhSH1vt
WqTqUID8MvivVt0CAwEAAaNjMGEwHwYDVR0RBBgwFoIUd3d3LnRlc3QuZXhhbXBs
ZS5jb20wHQYDVR0OBBYEFNwyblnHZK7oF2ZdJLThLL7hnZ69MB8GA1UdIwQYMBaA
FEYD1PUSu0sqtzBwgJQ4Nr37GBL6MA0GCSqGSIb3DQEBCwUAA4IBAQBkHTXTxIOg
hzXaWL2IKja/f0ZEnNaioFbhFbx4x8GuSJhoxT74xNLCKt2PNxEoM94qYArbRTUw
+BYbAKTlZdgQnfCuzXn6Ovjjh7qEyKuVjhlX6fz4AsJacW5QCvucozyfq8u1gZKq
wDsPjux7yHzLns5KrO/WLOOXIYyHVp+Ua1UmZZW7gFn6Yhw3TifkTgnYv48qzZWy
4jFb2YuPizB7IihqOWpEuAoS61YnfwkgMIkO7bsHwwmAHBXZCIvKDrA6pvLgKve/
mByZQOa+MvrcAx6n5JSgbpNTGKuww8mpqTMgOW7euI1T7jelsbA3u0araj6aA/J3
aUsdBfyfUZK3
-----END CERTIFICATE-----"""

WWW_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQD4AAzOrkk89ohO
Fd49K5PNpOVkhNx82fy0yKLgt+1Kfj8hO3785kKX2ju3gA7285mSWwZKlM8iIqE+
4gnGTnKJL2RsnxaX701tKrWJWdOsRmOGypVXKBZ7Y+xLI2R0BEeb3/ce2Jxv5egY
VAmdPPf2Rw4FYY1bGpnRIKYm5zCQXiWkZnzATdVWrW5ThkJ3FV8glhJDTipFq1w8
b81bZREWHCStAWd30f7H7bBktWptVSYAR0YCtNq15Q3HmWlRhk1ydRnuMPVW+BIC
VKMoZ8QXvy6p9frBefn0FlPTcMjmTmPvxQlN6DRw4aX9f2+fKK1YUh9b7Vqk6lCA
/DL4r1bdAgMBAAECggEAC3yEcKyHBQfodhtnr3QdqfxC9ACpA1myWBTkjF11zrSM
YSeTtmFw1f6G3l/T8ZwEnHrS+VstQSgS8/9n/f4YqndzjTS3c8KNlr/laBmXvFEx
9Lvce7dbhowGf/rBQT6zKrT5HxM1IwP7l72JXiBv3gGE/0/5H4OFeneVZ9RfPgnI
Qyfc60LNRmaODihfyd1c+dB8x2BOpSq6ysjpvNJef48Ve2ZpfQt3URtbkuqI1ZTT
IeEqXYidVxxfQ9k1bq04p7BOQER7ZX1TzlIJpOrjNYhtiUBLi1PPUa1Pp8kA9hC3
RoOku20FQZassddZT9rkkdJhRS8zRELNZgzSMsxVMQKBgQD/wALXx9FUAry+OM36
AimdDzP4HbHyFOjdkak8dDv0cltwi5MmPoMsrNDKchbKPbsvGZWknwsWpecNeCHt
x0oeLxQTSVGafO3zjpA8v9DIXVTxHBYVoccaL7FHpJgD/CBg2qtgZP3UmLm/afjI
SaaKHXYCNXLZi65FGislcO7aMQKBgQD4PhmTWQGZ38lR6pjbk+UsDvDFxYOltk/e
iWcdbpHeD2VVmK+iBqyJ4OtSD0HXFkeZBB3dPPthVxsoSfkSZQWueRzJrP+ZqFa2
/hgbsGv13cwSx6cx91kyXOwoGQEBb26w/tPvFkSUSw7HgOefPdH/aRTEWCYdUPnX
De8s8zdwbQKBgHgrdqqBX2CEML+I3W/d2EPOQvMQsO442PpTWRvo2csQeNq3Gptb
wDMbuLeHSCIbQ3rsIJ5LhOBNb/WqPvcFL1RjdqFhUBCxJvXMRQXmc2nSQPlR4yai
73Tkd/5b3nnw3B3mYaRXj9V3NcA1QQqLYM+A7FQ5XQ/PTEF3/FIJcJHhAoGAI+O+
iNoObDO5hHlZXi2UrXj/gGhc7yFbjL3qxYuN1T/+k5B+m/tBCLIW84c3KqSS92Fr
++dsJJeWWo3PT8SBPMdPzSyQy6NV3iEAVUh9Y0+MyI5K8uNi5vAeSHHM/msg4sAE
3gUnJxVu7pMJabFjYfzMPtLLt+NUK65dDO+g7UUCgYAOhj/MYB7emuSwLAL7g5PQ
mMT6QP8aLEzCiTlM3134Yu8Py/N5/5wbOvRgfmqbekHTyMEj85hiY6aGftB8P6YX
2yfHBuPssaRJvB7vRc13ssZ33g4O/qVK7KZYoQhBBkYcnwglYgg8j+4EuW3mHyVP
Zy3FId4yivtajMUu865euw==
-----END PRIVATE KEY-----"""

API_CERT = """-----BEGIN CERTIFICATE-----
MIIDlTCCAn2gAwIBAgIUOCU9p0Z5rkJksIl9EuEW5H+UFZMwDQYJKoZIhvcNAQEL
BQAwVjELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMQ0wCwYDVQQHDARVZW5v
MRIwEAYDVQQKDAlGb3JnZVNob3AxFDASBgNVBAMMC1Rlc3RGb3JnZUNBMB4XDTI2
MDIxOTAwMzMwM1oXDTM2MDIxNzAwMzMwM1owTjELMAkGA1UEBhMCSlAxDjAMBgNV
BAgMBVRva3lvMQ0wCwYDVQQHDARVZW5vMRIwEAYDVQQKDAlGb3JnZVNob3AxDDAK
BgNVBAMMA2FwaTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMAmxtyb
X5G8AdM14vAKOEIrTXEuuLBYCTSM9TSyE9hdp389nRRTf+6IIEX81PP3ONN0CgBG
2JoTW28X4Bc0IOQc6lTavl/OO1sCK+oPPfVbhg7RkpZtCm2XPE3zBUnH6xwmWCZV
tTfjkhZYNCtVawvzCV+D6tVMQ6DcBKPJS+jJ308Pu8tA0pzHZx13/lycqozEsoZn
yTWt9WXGjENDJMLPe9xT/FHgOACR97sp4jQzySbWDE0fzlBU+JUq0TuWosjjGi4h
m7NDxoF9rTAw7WrUUTmmizqO7O/wd+3oc2pFkEIVcMpNc90MN4qkPzbijDzpvcPK
miXjJhrB59O+Ky8CAwEAAaNjMGEwHwYDVR0RBBgwFoIUYXBpLnRlc3QuZXhhbXBs
ZS5jb20wHQYDVR0OBBYEFNUsoi6qCrMmR5h92mwyzo4xVREFMB8GA1UdIwQYMBaA
FEYD1PUSu0sqtzBwgJQ4Nr37GBL6MA0GCSqGSIb3DQEBCwUAA4IBAQCrJ0S0yQIz
B27QSycEN0kdbxqFhb/yqtv1FDkIs060cY1fAg3UOJHnrwjsh6w9UzeIJRZLylMK
446mE52NTfM71IbwPbpPeaGEm1uL3DDl+/x/YR6yDZW06nY8g6HwpFcCKceRctrx
kyCZ5IcviQkIbR2v3Z/azrfe4ZEqo7VgbgULNdJKbzG6jKpatdxleqzXWNg364Wg
AIKZqGJTKur0IuOeuBZiYxeWVMFzQ+3rIcntYAvM9rB1e44RPa/9kLZ1Nua7A4OA
m5m4Deh+O3Q2ZAusfd0MUwL6ZpwZYguCW5El+UUF9y94jVQh5eG9Y6sW9n6MZKKG
3DNO/pUXx3iQ
-----END CERTIFICATE-----"""

API_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDAJsbcm1+RvAHT
NeLwCjhCK01xLriwWAk0jPU0shPYXad/PZ0UU3/uiCBF/NTz9zjTdAoARtiaE1tv
F+AXNCDkHOpU2r5fzjtbAivqDz31W4YO0ZKWbQptlzxN8wVJx+scJlgmVbU345IW
WDQrVWsL8wlfg+rVTEOg3ASjyUvoyd9PD7vLQNKcx2cdd/5cnKqMxLKGZ8k1rfVl
xoxDQyTCz3vcU/xR4DgAkfe7KeI0M8km1gxNH85QVPiVKtE7lqLI4xouIZuzQ8aB
fa0wMO1q1FE5pos6juzv8Hft6HNqRZBCFXDKTXPdDDeKpD824ow86b3Dypol4yYa
wefTvisvAgMBAAECggEAIKK1ZeSxz7PJ75CYccKamYp3RcD0t2bMcXN7di7Ethv6
Bd92HWytLttJ9/kgRit4KFnuFOvzf//HqM+6TNaau4O5vR3F9cm2RRfSU5exI0of
M8ceiZQNkF1+bZLYFBbzdL2CfUhTViG9vzPN8Io6ezYVInbqXL3uQpT76MGYtfnA
GbVnFGNU/ntDJjq035U0ftPtydb/+LktxqwKG+0/rsqLqJNklTxDv/oZxclouDj0
UThTPnx3qOEqAlmLt1IWy0FnKdHnWR7YssAWDj3tuCUJ34yZiUicrkP2UgCO3qZU
s5VhjdMAZPqQnUP7V2gdDmTsTOdLf7cAzoWS3ZTfuQKBgQDopxTk5g6VWv6SeLmW
of5XRC9UcLAdic202lpIf0vxt+qeKdhDucWZf0/zNL0zKmol6imyKTH86ajpS00Q
AicnTpiE1ogXoHxvi9PpnwdG/rZnZqeZ4aDqWBHw1o0HiJoSL9qECibcdlfJJlmj
BFE0Y1lOy1pSYS9n4lz/Dbz90wKBgQDTbzUIBo7eqsStJKqlltSZzBS+bqioHOlq
zAID4CGGth10roa73liOK5FSyu8TUlVduwOZWHEjUJ7KvX3ZH4sUC0V9sbsFdteU
vmbjRl7wdDHsBMEkl2oFSXOR1R+O8zC9V8y79yDQTP44iEs9erpFO2y5Ky7ucNBX
cw4x3DRXtQKBgQDM3gRKJEOHRZ+Sf3h9qpx7X/GFm82Z1TUtInIKEP5hFiElsZdc
3AOizTcr5K8OlTTvuimJVzlLir5Q4Rw1EpBDzrQDlZ41n/6zgx/SQ1V3MOiSWRUR
Llwyv+bcezGpBqMVjMoRJ5dc32EiIgEgybZwOWP1PKCGlknWYsCdYA2iPQKBgE1s
2M+ijyjtAe6hkbfnntzfBe2iWjKNu9A2+rnulnhdMjYrPv2G84jEXYgi9h9uNAKJ
3EyIPY4AFNYLRA2BZo2lfwIDVogut80pWEX73AJTmoBiUVQT+mgLOL37fH39giik
AT4HxkVhHGsZRewyiAmYND0umhYIy9JqOJV7nNNNAoGASthPcSo/9TqVV1P7EdbC
PV8gW0VCSRj5lo6h/PuvlZ5MsND5ykjUWe7j0GdN8FIBJclKu0EZGH6L/VeKmGXI
+ncHZJqggQd80UZ2UCTltQTbufi1TD0PLug5Axcpv6nrmvIjWGV1PB/gPJCw68BU
t8lPOJeNU9q7aZP8lFgBCQ4=
-----END PRIVATE KEY-----"""

@pytest.fixture(scope="session", autouse=True)
def resolve_to_localhost(request):
    """
    Patch socket.getaddrinfo to resolve test domains to localhost.
    """
    original_getaddrinfo = socket.getaddrinfo
    def patched_getaddrinfo(*args):
        host = args[0]
        if host.endswith(".test.example.com") or host.endswith(".chip-in.net"):
            return original_getaddrinfo("127.0.0.1", *args[1:])
        return original_getaddrinfo(*args)
    
    socket.getaddrinfo = patched_getaddrinfo
    yield
    socket.getaddrinfo = original_getaddrinfo

@pytest.fixture(scope="session", autouse=True)
def apply_test_config():
    """
    Inject test routing and session configurations into chip-in-inventory.
    """
    inventory_url = os.getenv("APIGW_INVENTORY_URL", "http://localhost:3000/v1")

    # OIDC settings are now defined directly here instead of loading from a YAML file.
    oidc_config = {
        "client_id": "test-client",
        "client_secret": "secret",
        "issuer": "https://auth.test.example.com"
    }

    # Post resource to inventory, ignoring 409 Conflicts.
    def post_resource(path, data):
        url = f"{inventory_url}{path}"
        try:
            res = requests.post(url, json=data, timeout=5)
            if res.status_code == 409:
                return # Already exists
            if res.status_code >= 400:
                print(f"  Inventory API Error ({res.status_code}) at {path}: {res.text}")
                print(f"  Sent Payload: {data}")
            res.raise_for_status()
        except requests.exceptions.RequestException as e:
            pytest.fail(f"Failed to apply config to {url}: {e}")

    # --- 1. Realm Setup ---
    realm_name = "forge"
    zone_name = "test.example.com"
    
    # Create Realm
    realm_payload = {
        "name": realm_name,
        "title": "Integration Test Forge Realm",
        "cacert": CA_CERT.strip(),
        "deviceIdVerificationKey": DEVICE_VERIFY_PUB_KEY.strip(),
        "deviceIdSigningKey": DEVICE_SIGN_PRIV_KEY.strip(),
        "sessionTimeout": 2592000,
        "disabled": False
    }
    post_resource("/realms", realm_payload)

    # Create Zone and Subdomains
    post_resource(f"/realms/{realm_name}/zones", {
        "name": zone_name, "title": f"Zone {zone_name}"
    })
    for sub in ["www", "api", "auth", "database", "check", "betelgeuse"]:
        post_resource(f"/realms/{realm_name}/zones/{zone_name}/subdomains", {
            "name": sub, "title": sub, "fqdn": f"{sub}.{zone_name}"
        })

    # --- 2. Virtual Hosts ---
    vhosts = [
        {"name": "www", "cert": WWW_CERT, "key": WWW_KEY},
        {"name": "api", "cert": API_CERT, "key": API_KEY},
        {"name": "auth", "cert": API_CERT, "key": API_KEY},
        {"name": "check", "cert": API_CERT, "key": API_KEY},
        {"name": "betelgeuse", "cert": API_CERT, "key": API_KEY}
    ]
    for vh in vhosts:
        vh_payload = {
            "name": vh["name"],
            "title": vh["name"],
            "subdomain": f"urn:chip-in:subdomain:{realm_name}:{zone_name}:{vh['name']}",
            "certificate": vh["cert"].strip(),
            "key": vh["key"].strip()
        }
        post_resource(f"/realms/{realm_name}/virtual-hosts", vh_payload)

    # --- 3. Routing Rules ---
    rules = [
        {
            "match": "request.path.equals('/robot.txt')",
            "action": {
                "type": "returnStaticText",
                "content": "User-agent: *\nDisallow: /",
                "status": 200
            }
        },
        {
            "match": "request.path.starts_with('/external/')",
            "action": {
                "type": "redirect",
                "url": "https://ext.example.com/hello"
            }
        },
        {
            "match": "request.path.starts_with('/fruit/orange/')",
            "action": {
                "type": "setDownstreamResponseHeader",
                "name": "X-Powered-By",
                "value": "BFF-Proxy"
            }
        },
        {
            "match": "request.path.starts_with('/api/')",
            "action": {
                "type": "proxy",
                "upstream": "http://127.0.0.1:9000"
            }
        },
        {
            "match": "hostname.equals('api.test.example.com') and request.path.equals('/session-check')",
            "action": {
                "type": "proxy",
                "upstream": "http://127.0.0.1:9000",
                "authScopeName": "test-scope"
            }
        },
        {
            "match": "hostname.equals('www.test.example.com')",
            "action": {"type": "proxy", "upstream": "http://127.0.0.1:9000", "authScopeName": "test-scope"}
        },
        {
            "match": "hostname.equals('auth.test.example.com')",
            "action": {"type": "proxy", "upstream": "http://127.0.0.1:9000", "authScopeName": "test-scope"}
        },
        {
            "match": "hostname.equals('check.test.example.com')",
            "action": {"type": "proxy", "upstream": "http://127.0.0.1:9000", "authScopeName": "test-scope"}
        },
        {
            "match": "hostname.equals('api.test.example.com') and request.path.equals('/dashboard')",
            "action": {
                "type": "requireAuthentication",
                "protectedUpstream": "http://127.0.0.1:9000",
                "authScopeName": "test-scope",
                "oidcClientId": oidc_config.get("client_id", "test-client"),
                "oidcClientSecret": oidc_config.get("client_secret", "secret"),
                "oidcRedirectUrl": f"https://api.{zone_name}:8443/callback",
                "oidcAuthorizationEndpoint": f"{oidc_config.get('issuer')}/authorize",
                "oidcTokenEndpoint": f"{oidc_config.get('issuer')}/token"
            }
        }
    ]
    post_resource(f"/realms/{realm_name}/routing-chains", {
        "name": "test-route", "title": "Test Route", "rules": rules
    })

    # --- 4. Hubs and Services ---
    hub_name = "hub1"
    post_resource(f"/realms/{realm_name}/hubs", {
        "name": hub_name, "title": "Hub", "fqdn": f"hub1.{zone_name}",
        "serverAddress": "0.0.0.0", "serverPort": 4433,
        "serverCert": "dummy", "serverCertKey": "dummy"
    })
    for svc in ["www", "api", "auth", "database"]:
        post_resource(f"/realms/{realm_name}/hubs/{hub_name}/services", {
            "name": svc, "title": f"{svc} service",
            "provider": f"urn:chip-in:end-point:{zone_name}:{svc}-server",
            "consumers": [f"urn:chip-in:end-point:{zone_name}:{svc}-gateway"]
        })

    # Send SIGUSR1 to spngw to reload config immediately
    try:
        pid_str = subprocess.check_output(["pgrep", "-x", "spngw"]).decode().strip()
        pid = int(pid_str.split('\n')[0])
        os.kill(pid, signal.SIGUSR1)
    except (subprocess.CalledProcessError, ValueError, ProcessLookupError):
        # Skip if process not found
        pass

    # Wait for config reload
    time.sleep(1)

@pytest.fixture(scope="session", autouse=True)
def start_mocks():
    """
    Start mock servers in mock_servers/ in the background.
    """
    mocks_dir = os.path.join(os.path.dirname(__file__), "mock_servers")
    # mapping script to expected port for health checking
    mocks = {
        "httpserver.py": 9000
    }
    processes = []

    print("\nStarting mock servers...")
    for script, port in mocks.items():
        path = os.path.join(mocks_dir, script)
        if os.path.exists(path):
            # Pass port as argument
            if script == "httpserver.py":
                cmd = ["python3", path, "--ports", str(port)]
            else:
                cmd = ["python3", path, "--port", str(port)]
            proc = subprocess.Popen(cmd)
            processes.append(proc)
            
            # Wait for port to become active
            start_time = time.time()
            while time.time() - start_time < 5:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    if sock.connect_ex(('127.0.0.1', port)) == 0:
                        break
                time.sleep(0.5)
            else:
                print(f"  Warning: Mock server {script} on port {port} timed out starting.")

    yield

    # Cleanup mock servers
    print("\nStopping mock servers...")
    for proc in processes:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()