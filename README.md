# fido-ident

`fido-ident` is a cli tool for getting the attestation certificate from a fido token. `fido-ident` will print the raw certificate and the human readable parts it knows about.

`fido-ident` is aware of some of the fido and yubikey specific certificate extensions and will attempt to decode the ones it knows about. This can be useful for things like confirming a yubikey is FIPS certified or not.

See [Adam Langley's (agl) blog post on WebAuthn](https://www.imperialviolet.org/2018/03/27/webauthn.html) for more details about attestation certificates.

## Example

Here's an example running against a yubikey 5 series device.

```
$ ./fido-ident
2022/01/28 15:21:07 registering device, tap key to continue
pem:
-----BEGIN CERTIFICATE-----
MIICvjCCAaagAwIBAgIEXdBO4TANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ
dWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw
MDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1
YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYG
A1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTU3MzkzMjc2OTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABCNp4As+URnWqbTRh760QYDNrHHqUpiB4+d9HPWBoTtn
MSupMoY1ncNIDYET1l4UFOzm0Q67LR7I3Zo/Av1cgNSjbDBqMCIGCSsGAQQBgsQK
AgQVMS4zLjYuMS40LjEuNDE0ODIuMS43MBMGCysGAQQBguUcAgEBBAQDAgQwMCEG
CysGAQQBguUcAQEEBBIEEC/AV5+BE0fqsRa7Wo25ICowDAYDVR0TAQH/BAIwADAN
BgkqhkiG9w0BAQsFAAOCAQEAh8odJU4o9FIUYSm3h1UhrTGfnukczFJd3ojEJnxz
ZBnDBye7VfzVFJ05VQzu859HI3mRxK5FH4HLo6LnVrKrKh7cPEhECrQgEgbtjIwD
+AAXQkAAZT1eyng572o82o/6Ua9e0/N+BktXV3TwzPGgMQaWGgql41gyiRc+8YBB
bWF+ozozvRT2h+qexpd7YwPVk6FRiLhNyiqhl9qpnraHtrcQyEl++5PMnCUSygNy
KTzS9DH7d8G+qTFZV23bdecAyjS2EcfztFLSs0Au6+jLLvt9R0pjGW28kObE8F9B
BkJtLKZtPaw3W/LyZXOxs3PK+iENM5K3UtbbKPPi2a/AYQ==
-----END CERTIFICATE-----

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1573932769 (0x5dd04ee1)
    Signature Algorithm: SHA256-RSA
        Issuer: CN=Yubico U2F Root CA Serial 457200631
        Validity
            Not Before: Aug 1 00:00:00 2014 UTC
            Not After : Sep 4 00:00:00 2050 UTC
        Subject: C=SE,O=Yubico AB,OU=Authenticator Attestation,CN=Yubico U2F EE Serial 1573932769
        Subject Public Key Info:
            Public Key Algorithm: ECDSA
                Public-Key: (256 bit)
                X:
                    23:69:e0:0b:3e:51:19:d6:a9:b4:d1:87:be:b4:41:
                    80:cd:ac:71:ea:52:98:81:e3:e7:7d:1c:f5:81:a1:
                    3b:67
                Y:
                    31:2b:a9:32:86:35:9d:c3:48:0d:81:13:d6:5e:14:
                    14:ec:e6:d1:0e:bb:2d:1e:c8:dd:9a:3f:02:fd:5c:
                    80:d4
                Curve: P-256
        X509v3 extensions:
            1.3.6.1.4.1.41482.2 Yubikey U2FID: 1.3.6.1.4.1.41482.1.7
            1.3.6.1.4.1.45724.2.1.1 FIDO U2F Authenticator Transports Extension
            1.3.6.1.4.1.45724.1.1.4 AAGUID: 2fc0579f811347eab116bb5a8db9202a (YubiKey 5 NFC|YubiKey 5C NFC;fw5.2, 5.4)

            X509v3 Basic Constraints: critical
                CA:FALSE

    Signature Algorithm: SHA256-RSA
         87:ca:1d:25:4e:28:f4:52:14:61:29:b7:87:55:21:ad:31:9f:
         9e:e9:1c:cc:52:5d:de:88:c4:26:7c:73:64:19:c3:07:27:bb:
         55:fc:d5:14:9d:39:55:0c:ee:f3:9f:47:23:79:91:c4:ae:45:
         1f:81:cb:a3:a2:e7:56:b2:ab:2a:1e:dc:3c:48:44:0a:b4:20:
         12:06:ed:8c:8c:03:f8:00:17:42:40:00:65:3d:5e:ca:78:39:
         ef:6a:3c:da:8f:fa:51:af:5e:d3:f3:7e:06:4b:57:57:74:f0:
         cc:f1:a0:31:06:96:1a:0a:a5:e3:58:32:89:17:3e:f1:80:41:
         6d:61:7e:a3:3a:33:bd:14:f6:87:ea:9e:c6:97:7b:63:03:d5:
         93:a1:51:88:b8:4d:ca:2a:a1:97:da:a9:9e:b6:87:b6:b7:10:
         c8:49:7e:fb:93:cc:9c:25:12:ca:03:72:29:3c:d2:f4:31:fb:
         77:c1:be:a9:31:59:57:6d:db:75:e7:00:ca:34:b6:11:c7:f3:
         b4:52:d2:b3:40:2e:eb:e8:cb:2e:fb:7d:47:4a:63:19:6d:bc:
         90:e6:c4:f0:5f:41:06:42:6d:2c:a6:6d:3d:ac:37:5b:f2:f2:
         65:73:b1:b3:73:ca:fa:21:0d:33:92:b7:52:d6:db:28:f3:e2:
         d9:af:c0:61


```

## License and Copying

fido-ident is MIT licensed.

The code in certinfo is forked from https://github.com/grantae/certinfo. License and copyright info for that code can be found in [certinfo/LICENSE](certinfo/LICENSE) (also MIT).
