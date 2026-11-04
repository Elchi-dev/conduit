package hue

import "crypto/x509"

// hueRoots are the certificate authorities that sign Hue bridges'
// certificates, whose common name is the bridge id:
//
//   - C=NL, O=Philips Hue, CN=root-bridge (2017–2038), SHA-256
//     F0:BD:8E:65:09:E8:2F:77:4D:63:BC:00:9D:53:88:C9:69:FE:3D:CF:7D:6D:54:1D:63:51:B7:2B:89:8D:8A:CF,
//     for the square bridge (v2) since its 2020 firmware;
//   - C=NL, O=Signify Hue, CN=Hue Root CA 01 (2025–2050), SHA-256
//     D8:B8:94:48:B2:AF:8E:16:76:18:5A:C0:72:19:EE:9D:CB:C8:F0:1C:12:2A:02:6A:2A:4B:7B:5C:FE:03:28:B8,
//     for the Bridge Pro.
//
// The PEM is copied from openHAB's Hue binding (huebridge_cacert.pem) and
// is byte-identical to the copy in homebridge-hue's hb-hue-tools
// (HueClient.rootCertificates); Signify's own copy is on the Hue developer
// site ("Using HTTPS"), behind a login. Both are self-signed CAs (checked
// with openssl). To check a copy: openssl x509 -noout -fingerprint -sha256.
// Bridges with an older, self-signed certificate don't chain to them: pin
// such a bridge's fingerprint instead.
const hueRoots = `-----BEGIN CERTIFICATE-----
MIICMjCCAdigAwIBAgIUO7FSLbaxikuXAljzVaurLXWmFw4wCgYIKoZIzj0EAwIw
OTELMAkGA1UEBhMCTkwxFDASBgNVBAoMC1BoaWxpcHMgSHVlMRQwEgYDVQQDDAty
b290LWJyaWRnZTAiGA8yMDE3MDEwMTAwMDAwMFoYDzIwMzgwMTE5MDMxNDA3WjA5
MQswCQYDVQQGEwJOTDEUMBIGA1UECgwLUGhpbGlwcyBIdWUxFDASBgNVBAMMC3Jv
b3QtYnJpZGdlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjNw2tx2AplOf9x86
aTdvEcL1FU65QDxziKvBpW9XXSIcibAeQiKxegpq8Exbr9v6LBnYbna2VcaK0G22
jOKkTqOBuTCBtjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNV
HQ4EFgQUZ2ONTFrDT6o8ItRnKfqWKnHFGmQwdAYDVR0jBG0wa4AUZ2ONTFrDT6o8
ItRnKfqWKnHFGmShPaQ7MDkxCzAJBgNVBAYTAk5MMRQwEgYDVQQKDAtQaGlsaXBz
IEh1ZTEUMBIGA1UEAwwLcm9vdC1icmlkZ2WCFDuxUi22sYpLlwJY81Wrqy11phcO
MAoGCCqGSM49BAMCA0gAMEUCIEBYYEOsa07TH7E5MJnGw557lVkORgit2Rm1h3B2
sFgDAiEA1Fj/C3AN5psFMjo0//mrQebo0eKd3aWRx+pQY08mk48=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBzDCCAXOgAwIBAgICEAAwCgYIKoZIzj0EAwIwPDELMAkGA1UEBhMCTkwxFDAS
BgNVBAoMC1NpZ25pZnkgSHVlMRcwFQYDVQQDDA5IdWUgUm9vdCBDQSAwMTAgFw0y
NTAyMjUwMDAwMDBaGA8yMDUwMTIzMTIzNTk1OVowPDELMAkGA1UEBhMCTkwxFDAS
BgNVBAoMC1NpZ25pZnkgSHVlMRcwFQYDVQQDDA5IdWUgUm9vdCBDQSAwMTBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABFfOO0jfSAUXGQ9kjEDzyBrcMQ3ItyA5krE+
cyvb1Y3xFti7KlAad8UOnAx0FBLn7HZrlmIwm1QnX0fK3LPM13mjYzBhMB0GA1Ud
DgQWBBTF1pSpsCASX/z0VHLigxU2CAaqoTAfBgNVHSMEGDAWgBTF1pSpsCASX/z0
VHLigxU2CAaqoTAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAKBggq
hkjOPQQDAgNHADBEAiAk7duT+IHbOGO4UUuGLAEpyYejGZK9Z7V9oSfnvuQ5BQIg
IYSgwwxHXm73/JgcU9lAM6c8Bmu3UE3kBIUwBs1qXFw=
-----END CERTIFICATE-----
`

// bridgeRoots is the pool built from hueRoots.
var bridgeRoots = func() *x509.CertPool {
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM([]byte(hueRoots)) {
		panic("hue: the embedded root certificates don't parse")
	}
	return p
}()
