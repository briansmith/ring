/* Copyright (c) 2016, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <vector>

#include <assert.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/digest.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pool.h>
#include <openssl/x509.h>

#include "../internal.h"


static const char kCrossSigningRootPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICcTCCAdqgAwIBAgIIagJHiPvE0MowDQYJKoZIhvcNAQELBQAwPDEaMBgGA1UE\n"
    "ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
    "dCBDQTAgFw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowPDEaMBgGA1UE\n"
    "ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
    "dCBDQTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAwo3qFvSB9Zmlbpzn9wJp\n"
    "ikI75Rxkatez8VkLqyxbOhPYl2Haz8F5p1gDG96dCI6jcLGgu3AKT9uhEQyyUko5\n"
    "EKYasazSeA9CQrdyhPg0mkTYVETnPM1W/ebid1YtqQbq1CMWlq2aTDoSGAReGFKP\n"
    "RTdXAbuAXzpCfi/d8LqV13UCAwEAAaN6MHgwDgYDVR0PAQH/BAQDAgIEMB0GA1Ud\n"
    "JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAPBgNVHRMBAf8EBTADAQH/MBkGA1Ud\n"
    "DgQSBBBHKHC7V3Z/3oLvEZx0RZRwMBsGA1UdIwQUMBKAEEcocLtXdn/egu8RnHRF\n"
    "lHAwDQYJKoZIhvcNAQELBQADgYEAnglibsy6mGtpIXivtlcz4zIEnHw/lNW+r/eC\n"
    "CY7evZTmOoOuC/x9SS3MF9vawt1HFUummWM6ZgErqVBOXIB4//ykrcCgf5ZbF5Hr\n"
    "+3EFprKhBqYiXdD8hpBkrBoXwn85LPYWNd2TceCrx0YtLIprE2R5MB2RIq8y4Jk3\n"
    "YFXvkME=\n"
    "-----END CERTIFICATE-----\n";

static const char kRootCAPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICVTCCAb6gAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwLjEaMBgGA1UE\n"
    "ChMRQm9yaW5nU1NMIFRFU1RJTkcxEDAOBgNVBAMTB1Jvb3QgQ0EwIBcNMTUwMTAx\n"
    "MDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMC4xGjAYBgNVBAoTEUJvcmluZ1NTTCBU\n"
    "RVNUSU5HMRAwDgYDVQQDEwdSb290IENBMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB\n"
    "iQKBgQDpDn8RDOZa5oaDcPZRBy4CeBH1siSSOO4mYgLHlPE+oXdqwI/VImi2XeJM\n"
    "2uCFETXCknJJjYG0iJdrt/yyRFvZTQZw+QzGj+mz36NqhGxDWb6dstB2m8PX+plZ\n"
    "w7jl81MDvUnWs8yiQ/6twgu5AbhWKZQDJKcNKCEpqa6UW0r5nwIDAQABo3oweDAO\n"
    "BgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMA8G\n"
    "A1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIEEEA31wH7QC+4HH5UBCeMWQEwGwYDVR0j\n"
    "BBQwEoAQQDfXAftAL7gcflQEJ4xZATANBgkqhkiG9w0BAQsFAAOBgQDXylEK77Za\n"
    "kKeY6ZerrScWyZhrjIGtHFu09qVpdJEzrk87k2G7iHHR9CAvSofCgEExKtWNS9dN\n"
    "+9WiZp/U48iHLk7qaYXdEuO07No4BYtXn+lkOykE+FUxmA4wvOF1cTd2tdj3MzX2\n"
    "kfGIBAYhzGZWhY3JbhIfTEfY1PNM1pWChQ==\n"
    "-----END CERTIFICATE-----\n";

static const char kRootCrossSignedPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICYzCCAcygAwIBAgIIAj5CwoHlWuYwDQYJKoZIhvcNAQELBQAwPDEaMBgGA1UE\n"
    "ChMRQm9yaW5nU1NMIFRFU1RJTkcxHjAcBgNVBAMTFUNyb3NzLXNpZ25pbmcgUm9v\n"
    "dCBDQTAgFw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowLjEaMBgGA1UE\n"
    "ChMRQm9yaW5nU1NMIFRFU1RJTkcxEDAOBgNVBAMTB1Jvb3QgQ0EwgZ8wDQYJKoZI\n"
    "hvcNAQEBBQADgY0AMIGJAoGBAOkOfxEM5lrmhoNw9lEHLgJ4EfWyJJI47iZiAseU\n"
    "8T6hd2rAj9UiaLZd4kza4IURNcKSckmNgbSIl2u3/LJEW9lNBnD5DMaP6bPfo2qE\n"
    "bENZvp2y0Habw9f6mVnDuOXzUwO9SdazzKJD/q3CC7kBuFYplAMkpw0oISmprpRb\n"
    "SvmfAgMBAAGjejB4MA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggrBgEFBQcD\n"
    "AQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAZBgNVHQ4EEgQQQDfXAftAL7gc\n"
    "flQEJ4xZATAbBgNVHSMEFDASgBBHKHC7V3Z/3oLvEZx0RZRwMA0GCSqGSIb3DQEB\n"
    "CwUAA4GBAErTxYJ0en9HVRHAAr5OO5wuk5Iq3VMc79TMyQLCXVL8YH8Uk7KEwv+q\n"
    "9MEKZv2eR/Vfm4HlXlUuIqfgUXbwrAYC/YVVX86Wnbpy/jc73NYVCq8FEZeO+0XU\n"
    "90SWAPDdp+iL7aZdimnMtG1qlM1edmz8AKbrhN/R3IbA2CL0nCWV\n"
    "-----END CERTIFICATE-----\n";

static const char kIntermediatePEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICXjCCAcegAwIBAgIJAKJMH+7rscPcMA0GCSqGSIb3DQEBCwUAMC4xGjAYBgNV\n"
    "BAoTEUJvcmluZ1NTTCBURVNUSU5HMRAwDgYDVQQDEwdSb290IENBMCAXDTE1MDEw\n"
    "MTAwMDAwMFoYDzIxMDAwMTAxMDAwMDAwWjA2MRowGAYDVQQKExFCb3JpbmdTU0wg\n"
    "VEVTVElORzEYMBYGA1UEAxMPSW50ZXJtZWRpYXRlIENBMIGfMA0GCSqGSIb3DQEB\n"
    "AQUAA4GNADCBiQKBgQC7YtI0l8ocTYJ0gKyXTtPL4iMJCNY4OcxXl48jkncVG1Hl\n"
    "blicgNUa1r9m9YFtVkxvBinb8dXiUpEGhVg4awRPDcatlsBSEBuJkiZGYbRcAmSu\n"
    "CmZYnf6u3aYQ18SU8WqVERPpE4cwVVs+6kwlzRw0+XDoZAczu8ZezVhCUc6NbQID\n"
    "AQABo3oweDAOBgNVHQ8BAf8EBAMCAgQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG\n"
    "AQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wGQYDVR0OBBIEEIwaaKi1dttdV3sfjRSy\n"
    "BqMwGwYDVR0jBBQwEoAQQDfXAftAL7gcflQEJ4xZATANBgkqhkiG9w0BAQsFAAOB\n"
    "gQCvnolNWEHuQS8PFVVyuLR+FKBeUUdrVbSfHSzTqNAqQGp0C9fk5oCzDq6ZgTfY\n"
    "ESXM4cJhb3IAnW0UM0NFsYSKQJ50JZL2L3z5ZLQhHdbs4RmODGoC40BVdnJ4/qgB\n"
    "aGSh09eQRvAVmbVCviDK2ipkWNegdyI19jFfNP5uIkGlYg==\n"
    "-----END CERTIFICATE-----\n";

static const char kIntermediateSelfSignedPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICZjCCAc+gAwIBAgIJAKJMH+7rscPcMA0GCSqGSIb3DQEBCwUAMDYxGjAYBgNV\n"
    "BAoTEUJvcmluZ1NTTCBURVNUSU5HMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0Ew\n"
    "IBcNMTUwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMDYxGjAYBgNVBAoTEUJv\n"
    "cmluZ1NTTCBURVNUSU5HMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0EwgZ8wDQYJ\n"
    "KoZIhvcNAQEBBQADgY0AMIGJAoGBALti0jSXyhxNgnSArJdO08viIwkI1jg5zFeX\n"
    "jyOSdxUbUeVuWJyA1RrWv2b1gW1WTG8GKdvx1eJSkQaFWDhrBE8Nxq2WwFIQG4mS\n"
    "JkZhtFwCZK4KZlid/q7dphDXxJTxapURE+kThzBVWz7qTCXNHDT5cOhkBzO7xl7N\n"
    "WEJRzo1tAgMBAAGjejB4MA4GA1UdDwEB/wQEAwICBDAdBgNVHSUEFjAUBggrBgEF\n"
    "BQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAZBgNVHQ4EEgQQjBpoqLV2\n"
    "211Xex+NFLIGozAbBgNVHSMEFDASgBCMGmiotXbbXVd7H40UsgajMA0GCSqGSIb3\n"
    "DQEBCwUAA4GBALcccSrAQ0/EqQBsx0ZDTUydHXXNP2DrUkpUKmAXIe8McqIVSlkT\n"
    "6H4xz7z8VRKBo9j+drjjtCw2i0CQc8aOLxRb5WJ8eVLnaW2XRlUqAzhF0CrulfVI\n"
    "E4Vs6ZLU+fra1WAuIj6qFiigRja+3YkZArG8tMA9vtlhTX/g7YBZIkqH\n"
    "-----END CERTIFICATE-----\n";

static const char kLeafPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICXjCCAcegAwIBAgIIWjO48ufpunYwDQYJKoZIhvcNAQELBQAwNjEaMBgGA1UE\n"
    "ChMRQm9yaW5nU1NMIFRFU1RJTkcxGDAWBgNVBAMTD0ludGVybWVkaWF0ZSBDQTAg\n"
    "Fw0xNTAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowMjEaMBgGA1UEChMRQm9y\n"
    "aW5nU1NMIFRFU1RJTkcxFDASBgNVBAMTC2V4YW1wbGUuY29tMIGfMA0GCSqGSIb3\n"
    "DQEBAQUAA4GNADCBiQKBgQDD0U0ZYgqShJ7oOjsyNKyVXEHqeafmk/bAoPqY/h1c\n"
    "oPw2E8KmeqiUSoTPjG5IXSblOxcqpbAXgnjPzo8DI3GNMhAf8SYNYsoH7gc7Uy7j\n"
    "5x8bUrisGnuTHqkqH6d4/e7ETJ7i3CpR8bvK16DggEvQTudLipz8FBHtYhFakfdh\n"
    "TwIDAQABo3cwdTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEG\n"
    "CCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwGQYDVR0OBBIEEKN5pvbur7mlXjeMEYA0\n"
    "4nUwGwYDVR0jBBQwEoAQjBpoqLV2211Xex+NFLIGozANBgkqhkiG9w0BAQsFAAOB\n"
    "gQBj/p+JChp//LnXWC1k121LM/ii7hFzQzMrt70bny406SGz9jAjaPOX4S3gt38y\n"
    "rhjpPukBlSzgQXFg66y6q5qp1nQTD1Cw6NkKBe9WuBlY3iYfmsf7WT8nhlT1CttU\n"
    "xNCwyMX9mtdXdQicOfNjIGUCD5OLV5PgHFPRKiHHioBAhg==\n"
    "-----END CERTIFICATE-----\n";

static const char kLeafNoKeyUsagePEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICNTCCAZ6gAwIBAgIJAIFQGaLQ0G2mMA0GCSqGSIb3DQEBCwUAMDYxGjAYBgNV\n"
    "BAoTEUJvcmluZ1NTTCBURVNUSU5HMRgwFgYDVQQDEw9JbnRlcm1lZGlhdGUgQ0Ew\n"
    "IBcNMTUwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMDcxGjAYBgNVBAoTEUJv\n"
    "cmluZ1NTTCBURVNUSU5HMRkwFwYDVQQDExBldmlsLmV4YW1wbGUuY29tMIGfMA0G\n"
    "CSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOKoZe75NPz77EOaMMl4/0s3PyQw++zJvp\n"
    "ejHAxZiTPCJgMbEHLrSzNoHdopg+CLUH5bE4wTXM8w9Inv5P8OAFJt7gJuPUunmk\n"
    "j+NoU3QfzOR6BroePcz1vXX9jyVHRs087M/sLqWRHu9IR+/A+UTcBaWaFiDVUxtJ\n"
    "YOwFMwjNPQIDAQABo0gwRjAMBgNVHRMBAf8EAjAAMBkGA1UdDgQSBBBJfLEUWHq1\n"
    "27rZ1AVx2J5GMBsGA1UdIwQUMBKAEIwaaKi1dttdV3sfjRSyBqMwDQYJKoZIhvcN\n"
    "AQELBQADgYEALVKN2Y3LZJOtu6SxFIYKxbLaXhTGTdIjxipZhmbBRDFjbZjZZOTe\n"
    "6Oo+VDNPYco4rBexK7umYXJyfTqoY0E8dbiImhTcGTEj7OAB3DbBomgU1AYe+t2D\n"
    "uwBqh4Y3Eto+Zn4pMVsxGEfUpjzjZDel7bN1/oU/9KWPpDfywfUmjgk=\n"
    "-----END CERTIFICATE-----\n";

static const char kForgeryPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICZzCCAdCgAwIBAgIIdTlMzQoKkeMwDQYJKoZIhvcNAQELBQAwNzEaMBgGA1UE\n"
    "ChMRQm9yaW5nU1NMIFRFU1RJTkcxGTAXBgNVBAMTEGV2aWwuZXhhbXBsZS5jb20w\n"
    "IBcNMTUwMTAxMDAwMDAwWhgPMjEwMDAxMDEwMDAwMDBaMDoxGjAYBgNVBAoTEUJv\n"
    "cmluZ1NTTCBURVNUSU5HMRwwGgYDVQQDExNmb3JnZXJ5LmV4YW1wbGUuY29tMIGf\n"
    "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDADTwruBQZGb7Ay6s9HiYv5d1lwtEy\n"
    "xQdA2Sy8Rn8uA20Q4KgqwVY7wzIZ+z5Butrsmwb70gdG1XU+yRaDeE7XVoW6jSpm\n"
    "0sw35/5vJbTcL4THEFbnX0OPZnvpuZDFUkvVtq5kxpDWsVyM24G8EEq7kPih3Sa3\n"
    "OMhXVXF8kso6UQIDAQABo3cwdTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYI\n"
    "KwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwGQYDVR0OBBIEEEYJ/WHM\n"
    "8p64erPWIg4/liwwGwYDVR0jBBQwEoAQSXyxFFh6tdu62dQFcdieRjANBgkqhkiG\n"
    "9w0BAQsFAAOBgQA+zH7bHPElWRWJvjxDqRexmYLn+D3Aivs8XgXQJsM94W0EzSUf\n"
    "DSLfRgaQwcb2gg2xpDFoG+W0vc6O651uF23WGt5JaFFJJxqjII05IexfCNhuPmp4\n"
    "4UZAXPttuJXpn74IY1tuouaM06B3vXKZR+/ityKmfJvSwxacmFcK+2ziAg==\n"
    "-----END CERTIFICATE-----\n";

// kExamplePSSCert is an example RSA-PSS self-signed certificate, signed with
// the default hash functions.
static const char kExamplePSSCert[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIICYjCCAcagAwIBAgIJAI3qUyT6SIfzMBIGCSqGSIb3DQEBCjAFogMCAWowRTEL\n"
    "MAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVy\n"
    "bmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0xNDEwMDkxOTA5NTVaFw0xNTEwMDkxOTA5\n"
    "NTVaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQK\n"
    "DBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwgZ8wDQYJKoZIhvcNAQEBBQADgY0A\n"
    "MIGJAoGBAPi4bIO0vNmoV8CltFl2jFQdeesiUgR+0zfrQf2D+fCmhRU0dXFahKg8\n"
    "0u9aTtPel4rd/7vPCqqGkr64UOTNb4AzMHYTj8p73OxaymPHAyXvqIqDWHYg+hZ3\n"
    "13mSYwFIGth7Z/FSVUlO1m5KXNd6NzYM3t2PROjCpywrta9kS2EHAgMBAAGjUDBO\n"
    "MB0GA1UdDgQWBBTQQfuJQR6nrVrsNF1JEflVgXgfEzAfBgNVHSMEGDAWgBTQQfuJ\n"
    "QR6nrVrsNF1JEflVgXgfEzAMBgNVHRMEBTADAQH/MBIGCSqGSIb3DQEBCjAFogMC\n"
    "AWoDgYEASUy2RZcgNbNQZA0/7F+V1YTLEXwD16bm+iSVnzGwtexmQVEYIZG74K/w\n"
    "xbdZQdTbpNJkp1QPjPfh0zsatw6dmt5QoZ8K8No0DjR9dgf+Wvv5WJvJUIQBoAVN\n"
    "Z0IL+OQFz6+LcTHxD27JJCebrATXZA0wThGTQDm7crL+a+SujBY=\n"
    "-----END CERTIFICATE-----\n";

// kBadPSSCertPEM is a self-signed RSA-PSS certificate with bad parameters.
static const char kBadPSSCertPEM[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDdjCCAjqgAwIBAgIJANcwZLyfEv7DMD4GCSqGSIb3DQEBCjAxoA0wCwYJYIZI\n"
    "AWUDBAIBoRowGAYJKoZIhvcNAQEIMAsGCWCGSAFlAwQCAaIEAgIA3jAnMSUwIwYD\n"
    "VQQDDBxUZXN0IEludmFsaWQgUFNTIGNlcnRpZmljYXRlMB4XDTE1MTEwNDE2MDIz\n"
    "NVoXDTE1MTIwNDE2MDIzNVowJzElMCMGA1UEAwwcVGVzdCBJbnZhbGlkIFBTUyBj\n"
    "ZXJ0aWZpY2F0ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMTaM7WH\n"
    "qVCAGAIA+zL1KWvvASTrhlq+1ePdO7wsrWX2KiYoTYrJYTnxhLnn0wrHqApt79nL\n"
    "IBG7cfShyZqFHOY/IzlYPMVt+gPo293gw96Fds5JBsjhjkyGnOyr9OUntFqvxDbT\n"
    "IIFU7o9IdxD4edaqjRv+fegVE+B79pDk4s0ujsk6dULtCg9Rst0ucGFo19mr+b7k\n"
    "dbfn8pZ72ZNDJPueVdrUAWw9oll61UcYfk75XdrLk6JlL41GrYHc8KlfXf43gGQq\n"
    "QfrpHkg4Ih2cI6Wt2nhFGAzrlcorzLliQIUJRIhM8h4IgDfpBpaPdVQLqS2pFbXa\n"
    "5eQjqiyJwak2vJ8CAwEAAaNQME4wHQYDVR0OBBYEFCt180N4oGUt5LbzBwQ4Ia+2\n"
    "4V97MB8GA1UdIwQYMBaAFCt180N4oGUt5LbzBwQ4Ia+24V97MAwGA1UdEwQFMAMB\n"
    "Af8wMQYJKoZIhvcNAQEKMCSgDTALBglghkgBZQMEAgGhDTALBgkqhkiG9w0BAQii\n"
    "BAICAN4DggEBAAjBtm90lGxgddjc4Xu/nbXXFHVs2zVcHv/mqOZoQkGB9r/BVgLb\n"
    "xhHrFZ2pHGElbUYPfifdS9ztB73e1d4J+P29o0yBqfd4/wGAc/JA8qgn6AAEO/Xn\n"
    "plhFeTRJQtLZVl75CkHXgUGUd3h+ADvKtcBuW9dSUncaUrgNKR8u/h/2sMG38RWY\n"
    "DzBddC/66YTa3r7KkVUfW7yqRQfELiGKdcm+bjlTEMsvS+EhHup9CzbpoCx2Fx9p\n"
    "NPtFY3yEObQhmL1JyoCRWqBE75GzFPbRaiux5UpEkns+i3trkGssZzsOuVqHNTNZ\n"
    "lC9+9hPHIoc9UMmAQNo1vGIW3NWVoeGbaJ8=\n"
    "-----END CERTIFICATE-----\n";

static const char kRSAKey[] =
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXgIBAAKBgQDYK8imMuRi/03z0K1Zi0WnvfFHvwlYeyK9Na6XJYaUoIDAtB92\n"
    "kWdGMdAQhLciHnAjkXLI6W15OoV3gA/ElRZ1xUpxTMhjP6PyY5wqT5r6y8FxbiiF\n"
    "KKAnHmUcrgfVW28tQ+0rkLGMryRtrukXOgXBv7gcrmU7G1jC2a7WqmeI8QIDAQAB\n"
    "AoGBAIBy09Fd4DOq/Ijp8HeKuCMKTHqTW1xGHshLQ6jwVV2vWZIn9aIgmDsvkjCe\n"
    "i6ssZvnbjVcwzSoByhjN8ZCf/i15HECWDFFh6gt0P5z0MnChwzZmvatV/FXCT0j+\n"
    "WmGNB/gkehKjGXLLcjTb6dRYVJSCZhVuOLLcbWIV10gggJQBAkEA8S8sGe4ezyyZ\n"
    "m4e9r95g6s43kPqtj5rewTsUxt+2n4eVodD+ZUlCULWVNAFLkYRTBCASlSrm9Xhj\n"
    "QpmWAHJUkQJBAOVzQdFUaewLtdOJoPCtpYoY1zd22eae8TQEmpGOR11L6kbxLQsk\n"
    "aMly/DOnOaa82tqAGTdqDEZgSNmCeKKknmECQAvpnY8GUOVAubGR6c+W90iBuQLj\n"
    "LtFp/9ihd2w/PoDwrHZaoUYVcT4VSfJQog/k7kjE4MYXYWL8eEKg3WTWQNECQQDk\n"
    "104Wi91Umd1PzF0ijd2jXOERJU1wEKe6XLkYYNHWQAe5l4J4MWj9OdxFXAxIuuR/\n"
    "tfDwbqkta4xcux67//khAkEAvvRXLHTaa6VFzTaiiO8SaFsHV3lQyXOtMrBpB5jd\n"
    "moZWgjHvB2W9Ckn7sDqsPB+U2tyX0joDdQEyuiMECDY8oQ==\n"
    "-----END RSA PRIVATE KEY-----\n";

// kCRLTestRoot is a test root certificate. It has private key:
//
//     -----BEGIN RSA PRIVATE KEY-----
//     MIIEpAIBAAKCAQEAo16WiLWZuaymsD8n5SKPmxV1y6jjgr3BS/dUBpbrzd1aeFzN
//     lI8l2jfAnzUyp+I21RQ+nh/MhqjGElkTtK9xMn1Y+S9GMRh+5R/Du0iCb1tCZIPY
//     07Tgrb0KMNWe0v2QKVVruuYSgxIWodBfxlKO64Z8AJ5IbnWpuRqO6rctN9qUoMlT
//     IAB6dL4G0tDJ/PGFWOJYwOMEIX54bly2wgyYJVBKiRRt4f7n8H922qmvPNA9idmX
//     9G1VAtgV6x97XXi7ULORIQvn9lVQF6nTYDBJhyuPB+mLThbLP2o9orxGx7aCtnnB
//     ZUIxUvHNOI0FaSaZH7Fi0xsZ/GkG2HZe7ImPJwIDAQABAoIBAQCJF9MTHfHGkk+/
//     DwCXlA0Wg0e6hBuHl10iNobYkMWIl/xXjOknhYiqOqb181py76472SVC5ERprC+r
//     Lf0PXzqKuA117mnkwT2bYLCL9Skf8WEhoFLQNbVlloF6wYjqXcYgKYKh8HgQbZl4
//     aLg2YQl2NADTNABsUWj/4H2WEelsODVviqfFs725lFg9KHDI8zxAZXLzDt/M9uVL
//     GxJiX12tr0AwaeAFZ1oPM/y+LznM3N3+Ht3jHHw3jZ/u8Z1RdAmdpu3bZ6tbwGBr
//     9edsH5rKkm9aBvMrY7eX5VHqaqyRNFyG152ZOJh4XiiFG7EmgTPCpaHo50Y018Re
//     grVtk+FBAoGBANY3lY+V8ZOwMxSHes+kTnoimHO5Ob7nxrOC71i27x+4HHsYUeAr
//     /zOOghiDIn+oNkuiX5CIOWZKx159Bp65CPpCbTb/fh+HYnSgXFgCw7XptycO7LXM
//     5GwR5jSfpfzBFdYxjxoUzDMFBwTEYRTm0HkUHkH+s+ajjw5wqqbcGLcfAoGBAMM8
//     DKW6Tb66xsf708f0jonAjKYTLZ+WOcwsBEWSFHoY8dUjvW5gqx5acHTEsc5ZTeh4
//     BCFLa+Mn9cuJWVJNs09k7Xb2PNl92HQ4GN2vbdkJhExbkT6oLDHg1hVD0w8KLfz1
//     lTAW6pS+6CdOHMEJpvqx89EgU/1GgIQ1fXYczE75AoGAKeJoXdDFkUjsU+FBhAPu
//     TDcjc80Nm2QaF9NMFR5/lsYa236f06MGnQAKM9zADBHJu/Qdl1brUjLg1HrBppsr
//     RDNkw1IlSOjhuUf5hkPUHGd8Jijm440SRIcjabqla8wdBupdvo2+d2NOQgJbsQiI
//     ToQ+fkzcxAXK3Nnuo/1436UCgYBjLH7UNOZHS8OsVM0I1r8NVKVdu4JCfeJQR8/H
//     s2P5ffBir+wLRMnH+nMDreMQiibcPxMCArkERAlE4jlgaJ38Z62E76KLbLTmnJRt
//     EC9Bv+bXjvAiHvWMRMUbOj/ddPNVez7Uld+FvdBaHwDWQlvzHzBWfBCOKSEhh7Z6
//     qDhUqQKBgQDPMDx2i5rfmQp3imV9xUcCkIRsyYQVf8Eo7NV07IdUy/otmksgn4Zt
//     Lbf3v2dvxOpTNTONWjp2c+iUQo8QxJCZr5Sfb21oQ9Ktcrmc/CY7LeBVDibXwxdM
//     vRG8kBzvslFWh7REzC3u06GSVhyKDfW93kN2cKVwGoahRlhj7oHuZQ==
//     -----END RSA PRIVATE KEY-----
static const char kCRLTestRoot[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDbzCCAlegAwIBAgIJAODri7v0dDUFMA0GCSqGSIb3DQEBCwUAME4xCzAJBgNV\n"
    "BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBW\n"
    "aWV3MRIwEAYDVQQKDAlCb3JpbmdTU0wwHhcNMTYwOTI2MTUwNjI2WhcNMjYwOTI0\n"
    "MTUwNjI2WjBOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQG\n"
    "A1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJQm9yaW5nU1NMMIIBIjANBgkq\n"
    "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAo16WiLWZuaymsD8n5SKPmxV1y6jjgr3B\n"
    "S/dUBpbrzd1aeFzNlI8l2jfAnzUyp+I21RQ+nh/MhqjGElkTtK9xMn1Y+S9GMRh+\n"
    "5R/Du0iCb1tCZIPY07Tgrb0KMNWe0v2QKVVruuYSgxIWodBfxlKO64Z8AJ5IbnWp\n"
    "uRqO6rctN9qUoMlTIAB6dL4G0tDJ/PGFWOJYwOMEIX54bly2wgyYJVBKiRRt4f7n\n"
    "8H922qmvPNA9idmX9G1VAtgV6x97XXi7ULORIQvn9lVQF6nTYDBJhyuPB+mLThbL\n"
    "P2o9orxGx7aCtnnBZUIxUvHNOI0FaSaZH7Fi0xsZ/GkG2HZe7ImPJwIDAQABo1Aw\n"
    "TjAdBgNVHQ4EFgQUWPt3N5cZ/CRvubbrkqfBnAqhq94wHwYDVR0jBBgwFoAUWPt3\n"
    "N5cZ/CRvubbrkqfBnAqhq94wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC\n"
    "AQEAORu6M0MOwXy+3VEBwNilfTxyqDfruQsc1jA4PT8Oe8zora1WxE1JB4q2FJOz\n"
    "EAuM3H/NXvEnBuN+ITvKZAJUfm4NKX97qmjMJwLKWe1gVv+VQTr63aR7mgWJReQN\n"
    "XdMztlVeZs2dppV6uEg3ia1X0G7LARxGpA9ETbMyCpb39XxlYuTClcbA5ftDN99B\n"
    "3Xg9KNdd++Ew22O3HWRDvdDpTO/JkzQfzi3sYwUtzMEonENhczJhGf7bQMmvL/w5\n"
    "24Wxj4Z7KzzWIHsNqE/RIs6RV3fcW61j/mRgW2XyoWnMVeBzvcJr9NXp4VQYmFPw\n"
    "amd8GKMZQvP0ufGnUn7D7uartA==\n"
    "-----END CERTIFICATE-----\n";

static const char kCRLTestLeaf[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDkDCCAnigAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwTjELMAkGA1UEBhMCVVMx\n"
    "EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxEjAQ\n"
    "BgNVBAoMCUJvcmluZ1NTTDAeFw0xNjA5MjYxNTA4MzFaFw0xNzA5MjYxNTA4MzFa\n"
    "MEsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQKDAlC\n"
    "b3JpbmdTU0wxEzARBgNVBAMMCmJvcmluZy5zc2wwggEiMA0GCSqGSIb3DQEBAQUA\n"
    "A4IBDwAwggEKAoIBAQDc5v1S1M0W+QWM+raWfO0LH8uvqEwuJQgODqMaGnSlWUx9\n"
    "8iQcnWfjyPja3lWg9K62hSOFDuSyEkysKHDxijz5R93CfLcfnVXjWQDJe7EJTTDP\n"
    "ozEvxN6RjAeYv7CF000euYr3QT5iyBjg76+bon1p0jHZBJeNPP1KqGYgyxp+hzpx\n"
    "e0gZmTlGAXd8JQK4v8kpdYwD6PPifFL/jpmQpqOtQmH/6zcLjY4ojmqpEdBqIKIX\n"
    "+saA29hMq0+NK3K+wgg31RU+cVWxu3tLOIiesETkeDgArjWRS1Vkzbi4v9SJxtNu\n"
    "OZuAxWiynRJw3JwH/OFHYZIvQqz68ZBoj96cepjPAgMBAAGjezB5MAkGA1UdEwQC\n"
    "MAAwLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmljYXRl\n"
    "MB0GA1UdDgQWBBTGn0OVVh/aoYt0bvEKG+PIERqnDzAfBgNVHSMEGDAWgBRY+3c3\n"
    "lxn8JG+5tuuSp8GcCqGr3jANBgkqhkiG9w0BAQsFAAOCAQEAd2nM8gCQN2Dc8QJw\n"
    "XSZXyuI3DBGGCHcay/3iXu0JvTC3EiQo8J6Djv7WLI0N5KH8mkm40u89fJAB2lLZ\n"
    "ShuHVtcC182bOKnePgwp9CNwQ21p0rDEu/P3X46ZvFgdxx82E9xLa0tBB8PiPDWh\n"
    "lV16jbaKTgX5AZqjnsyjR5o9/mbZVupZJXx5Syq+XA8qiJfstSYJs4KyKK9UOjql\n"
    "ICkJVKpi2ahDBqX4MOH4SLfzVk8pqSpviS6yaA1RXqjpkxiN45WWaXDldVHMSkhC\n"
    "5CNXsXi4b1nAntu89crwSLA3rEwzCWeYj+BX7e1T9rr3oJdwOU/2KQtW1js1yQUG\n"
    "tjJMFw==\n"
    "-----END CERTIFICATE-----\n";

static const char kBasicCRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBpzCBkAIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n"
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoA4wDDAKBgNV\n"
    "HRQEAwIBATANBgkqhkiG9w0BAQsFAAOCAQEAnrBKKgvd9x9zwK9rtUvVeFeJ7+LN\n"
    "ZEAc+a5oxpPNEsJx6hXoApYEbzXMxuWBQoCs5iEBycSGudct21L+MVf27M38KrWo\n"
    "eOkq0a2siqViQZO2Fb/SUFR0k9zb8xl86Zf65lgPplALun0bV/HT7MJcl04Tc4os\n"
    "dsAReBs5nqTGNEd5AlC1iKHvQZkM//MD51DspKnDpsDiUVi54h9C1SpfZmX8H2Vv\n"
    "diyu0fZ/bPAM3VAGawatf/SyWfBMyKpoPXEG39oAzmjjOj8en82psn7m474IGaho\n"
    "/vBbhl1ms5qQiLYPjm4YELtnXQoFyC72tBjbdFd/ZE9k4CNKDbxFUXFbkw==\n"
    "-----END X509 CRL-----\n";

static const char kRevokedCRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBvjCBpwIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n"
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEyNDRaFw0xNjEwMjYxNTEyNDRaMBUwEwICEAAX\n"
    "DTE2MDkyNjE1MTIyNlqgDjAMMAoGA1UdFAQDAgECMA0GCSqGSIb3DQEBCwUAA4IB\n"
    "AQCUGaM4DcWzlQKrcZvI8TMeR8BpsvQeo5BoI/XZu2a8h//PyRyMwYeaOM+3zl0d\n"
    "sjgCT8b3C1FPgT+P2Lkowv7rJ+FHJRNQkogr+RuqCSPTq65ha4WKlRGWkMFybzVH\n"
    "NloxC+aU3lgp/NlX9yUtfqYmJek1CDrOOGPrAEAwj1l/BUeYKNGqfBWYJQtPJu+5\n"
    "OaSvIYGpETCZJscUWODmLEb/O3DM438vLvxonwGqXqS0KX37+CHpUlyhnSovxXxp\n"
    "Pz4aF+L7OtczxL0GYtD2fR9B7TDMqsNmHXgQrixvvOY7MUdLGbd4RfJL3yA53hyO\n"
    "xzfKY2TzxLiOmctG0hXFkH5J\n"
    "-----END X509 CRL-----\n";

static const char kBadIssuerCRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBwjCBqwIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEWMBQGA1UECgwN\n"
    "Tm90IEJvcmluZ1NTTBcNMTYwOTI2MTUxMjQ0WhcNMTYxMDI2MTUxMjQ0WjAVMBMC\n"
    "AhAAFw0xNjA5MjYxNTEyMjZaoA4wDDAKBgNVHRQEAwIBAjANBgkqhkiG9w0BAQsF\n"
    "AAOCAQEAlBmjOA3Fs5UCq3GbyPEzHkfAabL0HqOQaCP12btmvIf/z8kcjMGHmjjP\n"
    "t85dHbI4Ak/G9wtRT4E/j9i5KML+6yfhRyUTUJKIK/kbqgkj06uuYWuFipURlpDB\n"
    "cm81RzZaMQvmlN5YKfzZV/clLX6mJiXpNQg6zjhj6wBAMI9ZfwVHmCjRqnwVmCUL\n"
    "TybvuTmkryGBqREwmSbHFFjg5ixG/ztwzON/Ly78aJ8Bql6ktCl9+/gh6VJcoZ0q\n"
    "L8V8aT8+Ghfi+zrXM8S9BmLQ9n0fQe0wzKrDZh14EK4sb7zmOzFHSxm3eEXyS98g\n"
    "Od4cjsc3ymNk88S4jpnLRtIVxZB+SQ==\n"
    "-----END X509 CRL-----\n";

// kKnownCriticalCRL is kBasicCRL but with a critical issuing distribution point
// extension.
static const char kKnownCriticalCRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBujCBowIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n"
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoCEwHzAKBgNV\n"
    "HRQEAwIBATARBgNVHRwBAf8EBzAFoQMBAf8wDQYJKoZIhvcNAQELBQADggEBAA+3\n"
    "i+5e5Ub8sccfgOBs6WVJFI9c8gvJjrJ8/dYfFIAuCyeocs7DFXn1n13CRZ+URR/Q\n"
    "mVWgU28+xeusuSPYFpd9cyYTcVyNUGNTI3lwgcE/yVjPaOmzSZKdPakApRxtpKKQ\n"
    "NN/56aQz3bnT/ZSHQNciRB8U6jiD9V30t0w+FDTpGaG+7bzzUH3UVF9xf9Ctp60A\n"
    "3mfLe0scas7owSt4AEFuj2SPvcE7yvdOXbu+IEv21cEJUVExJAbhvIweHXh6yRW+\n"
    "7VVeiNzdIjkZjyTmAzoXGha4+wbxXyBRbfH+XWcO/H+8nwyG8Gktdu2QB9S9nnIp\n"
    "o/1TpfOMSGhMyMoyPrk=\n"
    "-----END X509 CRL-----\n";

// kUnknownCriticalCRL is kBasicCRL but with an unknown critical extension.
static const char kUnknownCriticalCRL[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBvDCBpQIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n"
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoCMwITAKBgNV\n"
    "HRQEAwIBATATBgwqhkiG9xIEAYS3CQABAf8EADANBgkqhkiG9w0BAQsFAAOCAQEA\n"
    "GvBP0xqL509InMj/3493YVRV+ldTpBv5uTD6jewzf5XdaxEQ/VjTNe5zKnxbpAib\n"
    "Kf7cwX0PMSkZjx7k7kKdDlEucwVvDoqC+O9aJcqVmM6GDyNb9xENxd0XCXja6MZC\n"
    "yVgP4AwLauB2vSiEprYJyI1APph3iAEeDm60lTXX/wBM/tupQDDujKh2GPyvBRfJ\n"
    "+wEDwGg3ICwvu4gO4zeC5qnFR+bpL9t5tOMAQnVZ0NWv+k7mkd2LbHdD44dxrfXC\n"
    "nhtfERx99SDmC/jtUAJrGhtCO8acr7exCeYcduN7KKCm91OeCJKK6OzWst0Og1DB\n"
    "kwzzU2rL3G65CrZ7H0SZsQ==\n"
    "-----END X509 CRL-----\n";

// kUnknownCriticalCRL2 is kBasicCRL but with a critical issuing distribution
// point extension followed by an unknown critical extension
static const char kUnknownCriticalCRL2[] =
    "-----BEGIN X509 CRL-----\n"
    "MIIBzzCBuAIBATANBgkqhkiG9w0BAQsFADBOMQswCQYDVQQGEwJVUzETMBEGA1UE\n"
    "CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzESMBAGA1UECgwJ\n"
    "Qm9yaW5nU1NMFw0xNjA5MjYxNTEwNTVaFw0xNjEwMjYxNTEwNTVaoDYwNDAKBgNV\n"
    "HRQEAwIBATARBgNVHRwBAf8EBzAFoQMBAf8wEwYMKoZIhvcSBAGEtwkAAQH/BAAw\n"
    "DQYJKoZIhvcNAQELBQADggEBACTcpQC8jXL12JN5YzOcQ64ubQIe0XxRAd30p7qB\n"
    "BTXGpgqBjrjxRfLms7EBYodEXB2oXMsDq3km0vT1MfYdsDD05S+SQ9CDsq/pUfaC\n"
    "E2WNI5p8WircRnroYvbN2vkjlRbMd1+yNITohXYXCJwjEOAWOx3XIM10bwPYBv4R\n"
    "rDobuLHoMgL3yHgMHmAkP7YpkBucNqeBV8cCdeAZLuhXFWi6yfr3r/X18yWbC/r2\n"
    "2xXdkrSqXLFo7ToyP8YKTgiXpya4x6m53biEYwa2ULlas0igL6DK7wjYZX95Uy7H\n"
    "GKljn9weIYiMPV/BzGymwfv2EW0preLwtyJNJPaxbdin6Jc=\n"
    "-----END X509 CRL-----\n";

// CertFromPEM parses the given, NUL-terminated pem block and returns an
// |X509*|.
static bssl::UniquePtr<X509> CertFromPEM(const char *pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, strlen(pem)));
  return bssl::UniquePtr<X509>(
      PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
}

// CRLFromPEM parses the given, NUL-terminated pem block and returns an
// |X509_CRL*|.
static bssl::UniquePtr<X509_CRL> CRLFromPEM(const char *pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, strlen(pem)));
  return bssl::UniquePtr<X509_CRL>(
      PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr));
}

// PrivateKeyFromPEM parses the given, NUL-terminated pem block and returns an
// |EVP_PKEY*|.
static bssl::UniquePtr<EVP_PKEY> PrivateKeyFromPEM(const char *pem) {
  bssl::UniquePtr<BIO> bio(
      BIO_new_mem_buf(const_cast<char *>(pem), strlen(pem)));
  return bssl::UniquePtr<EVP_PKEY>(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

// CertsToStack converts a vector of |X509*| to an OpenSSL STACK_OF(X509),
// bumping the reference counts for each certificate in question.
static bssl::UniquePtr<STACK_OF(X509)> CertsToStack(
    const std::vector<X509 *> &certs) {
  bssl::UniquePtr<STACK_OF(X509)> stack(sk_X509_new_null());
  if (!stack) {
    return nullptr;
  }
  for (auto cert : certs) {
    if (!sk_X509_push(stack.get(), cert)) {
      return nullptr;
    }
    X509_up_ref(cert);
  }

  return stack;
}

// CRLsToStack converts a vector of |X509_CRL*| to an OpenSSL
// STACK_OF(X509_CRL), bumping the reference counts for each CRL in question.
static bssl::UniquePtr<STACK_OF(X509_CRL)> CRLsToStack(
    const std::vector<X509_CRL *> &crls) {
  bssl::UniquePtr<STACK_OF(X509_CRL)> stack(sk_X509_CRL_new_null());
  if (!stack) {
    return nullptr;
  }
  for (auto crl : crls) {
    if (!sk_X509_CRL_push(stack.get(), crl)) {
      return nullptr;
    }
    X509_CRL_up_ref(crl);
  }

  return stack;
}

static int Verify(X509 *leaf, const std::vector<X509 *> &roots,
                   const std::vector<X509 *> &intermediates,
                   const std::vector<X509_CRL *> &crls,
                   unsigned long flags,
                   bool use_additional_untrusted) {
  bssl::UniquePtr<STACK_OF(X509)> roots_stack(CertsToStack(roots));
  bssl::UniquePtr<STACK_OF(X509)> intermediates_stack(
      CertsToStack(intermediates));
  bssl::UniquePtr<STACK_OF(X509_CRL)> crls_stack(CRLsToStack(crls));

  if (!roots_stack ||
      !intermediates_stack ||
      !crls_stack) {
    return X509_V_ERR_UNSPECIFIED;
  }

  bssl::UniquePtr<X509_STORE_CTX> ctx(X509_STORE_CTX_new());
  bssl::UniquePtr<X509_STORE> store(X509_STORE_new());
  if (!ctx ||
      !store) {
    return X509_V_ERR_UNSPECIFIED;
  }

  if (use_additional_untrusted) {
    X509_STORE_set0_additional_untrusted(store.get(),
                                         intermediates_stack.get());
  }

  if (!X509_STORE_CTX_init(
          ctx.get(), store.get(), leaf,
          use_additional_untrusted ? nullptr : intermediates_stack.get())) {
    return X509_V_ERR_UNSPECIFIED;
  }

  X509_STORE_CTX_trusted_stack(ctx.get(), roots_stack.get());
  X509_STORE_CTX_set0_crls(ctx.get(), crls_stack.get());

  X509_VERIFY_PARAM *param = X509_VERIFY_PARAM_new();
  if (param == nullptr) {
    return X509_V_ERR_UNSPECIFIED;
  }
  X509_VERIFY_PARAM_set_time(param, 1474934400 /* Sep 27th, 2016 */);
  X509_VERIFY_PARAM_set_depth(param, 16);
  if (flags) {
    X509_VERIFY_PARAM_set_flags(param, flags);
  }
  X509_STORE_CTX_set0_param(ctx.get(), param);

  ERR_clear_error();
  if (X509_verify_cert(ctx.get()) != 1) {
    return X509_STORE_CTX_get_error(ctx.get());
  }

  return X509_V_OK;
}

static int Verify(X509 *leaf, const std::vector<X509 *> &roots,
                   const std::vector<X509 *> &intermediates,
                   const std::vector<X509_CRL *> &crls,
                   unsigned long flags = 0) {
  const int r1 = Verify(leaf, roots, intermediates, crls, flags, false);
  const int r2 = Verify(leaf, roots, intermediates, crls, flags, true);

  if (r1 != r2) {
    fprintf(stderr,
            "Verify with, and without, use_additional_untrusted gave different "
            "results: %d vs %d.\n",
            r1, r2);
    return false;
  }

  return r1;
}

static bool TestVerify() {
  bssl::UniquePtr<X509> cross_signing_root(CertFromPEM(kCrossSigningRootPEM));
  bssl::UniquePtr<X509> root(CertFromPEM(kRootCAPEM));
  bssl::UniquePtr<X509> root_cross_signed(CertFromPEM(kRootCrossSignedPEM));
  bssl::UniquePtr<X509> intermediate(CertFromPEM(kIntermediatePEM));
  bssl::UniquePtr<X509> intermediate_self_signed(
      CertFromPEM(kIntermediateSelfSignedPEM));
  bssl::UniquePtr<X509> leaf(CertFromPEM(kLeafPEM));
  bssl::UniquePtr<X509> leaf_no_key_usage(CertFromPEM(kLeafNoKeyUsagePEM));
  bssl::UniquePtr<X509> forgery(CertFromPEM(kForgeryPEM));

  if (!cross_signing_root ||
      !root ||
      !root_cross_signed ||
      !intermediate ||
      !intermediate_self_signed ||
      !leaf ||
      !leaf_no_key_usage ||
      !forgery) {
    fprintf(stderr, "Failed to parse certificates\n");
    return false;
  }

  std::vector<X509*> empty;
  std::vector<X509_CRL*> empty_crls;
  if (Verify(leaf.get(), empty, empty, empty_crls) !=
      X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
    fprintf(stderr, "Leaf verified with no roots!\n");
    return false;
  }

  if (Verify(leaf.get(), empty, {intermediate.get()}, empty_crls) !=
      X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
    fprintf(stderr, "Leaf verified with no roots!\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()}, {intermediate.get()}, empty_crls) !=
      X509_V_OK) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Basic chain didn't verify.\n");
    return false;
  }

  if (Verify(leaf.get(), {cross_signing_root.get()},
             {intermediate.get(), root_cross_signed.get()},
             empty_crls) != X509_V_OK) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Cross-signed chain didn't verify.\n");
    return false;
  }

  if (Verify(leaf.get(), {cross_signing_root.get(), root.get()},
             {intermediate.get(), root_cross_signed.get()},
             empty_crls) != X509_V_OK) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Cross-signed chain with root didn't verify.\n");
    return false;
  }

  /* This is the “altchains” test – we remove the cross-signing CA but include
   * the cross-sign in the intermediates. */
  if (Verify(leaf.get(), {root.get()},
             {intermediate.get(), root_cross_signed.get()},
             empty_crls) != X509_V_OK) {
    ERR_print_errors_fp(stderr);
    fprintf(stderr, "Chain with cross-sign didn't backtrack to find root.\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()},
             {intermediate.get(), root_cross_signed.get()}, empty_crls,
             X509_V_FLAG_NO_ALT_CHAINS) !=
      X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) {
    fprintf(stderr, "Altchains test still passed when disabled.\n");
    return false;
  }

  if (Verify(forgery.get(), {intermediate_self_signed.get()},
             {leaf_no_key_usage.get()},
             empty_crls) != X509_V_ERR_INVALID_CA) {
    fprintf(stderr, "Basic constraints weren't checked.\n");
    return false;
  }

  /* Test that one cannot skip Basic Constraints checking with a contorted set
   * of roots and intermediates. This is a regression test for CVE-2015-1793. */
  if (Verify(forgery.get(),
             {intermediate_self_signed.get(), root_cross_signed.get()},
             {leaf_no_key_usage.get(), intermediate.get()},
             empty_crls) != X509_V_ERR_INVALID_CA) {
    fprintf(stderr, "Basic constraints weren't checked.\n");
    return false;
  }

  return true;
}

static bool TestCRL() {
  bssl::UniquePtr<X509> root(CertFromPEM(kCRLTestRoot));
  bssl::UniquePtr<X509> leaf(CertFromPEM(kCRLTestLeaf));
  bssl::UniquePtr<X509_CRL> basic_crl(CRLFromPEM(kBasicCRL));
  bssl::UniquePtr<X509_CRL> revoked_crl(CRLFromPEM(kRevokedCRL));
  bssl::UniquePtr<X509_CRL> bad_issuer_crl(CRLFromPEM(kBadIssuerCRL));
  bssl::UniquePtr<X509_CRL> known_critical_crl(CRLFromPEM(kKnownCriticalCRL));
  bssl::UniquePtr<X509_CRL> unknown_critical_crl(
      CRLFromPEM(kUnknownCriticalCRL));
  bssl::UniquePtr<X509_CRL> unknown_critical_crl2(
      CRLFromPEM(kUnknownCriticalCRL2));

  if (!root ||
      !leaf ||
      !basic_crl ||
      !revoked_crl ||
      !bad_issuer_crl ||
      !known_critical_crl ||
      !unknown_critical_crl ||
      !unknown_critical_crl2) {
    fprintf(stderr, "Failed to parse certificates and CRLs.\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()}, {root.get()}, {basic_crl.get()},
             X509_V_FLAG_CRL_CHECK) != X509_V_OK) {
    fprintf(stderr, "Cert with CRL didn't verify.\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()}, {root.get()},
             {basic_crl.get(), revoked_crl.get()},
             X509_V_FLAG_CRL_CHECK) != X509_V_ERR_CERT_REVOKED) {
    fprintf(stderr, "Revoked CRL wasn't checked.\n");
    return false;
  }

  std::vector<X509_CRL *> empty_crls;
  if (Verify(leaf.get(), {root.get()}, {root.get()}, empty_crls,
             X509_V_FLAG_CRL_CHECK) != X509_V_ERR_UNABLE_TO_GET_CRL) {
    fprintf(stderr, "CRLs were not required.\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()}, {root.get()}, {bad_issuer_crl.get()},
             X509_V_FLAG_CRL_CHECK) != X509_V_ERR_UNABLE_TO_GET_CRL) {
    fprintf(stderr, "Bad CRL issuer was unnoticed.\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()}, {root.get()}, {known_critical_crl.get()},
             X509_V_FLAG_CRL_CHECK) != X509_V_OK) {
    fprintf(stderr, "CRL with known critical extension was rejected.\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()}, {root.get()},
             {unknown_critical_crl.get()}, X509_V_FLAG_CRL_CHECK) !=
      X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION) {
    fprintf(stderr, "CRL with unknown critical extension was accepted.\n");
    return false;
  }

  if (Verify(leaf.get(), {root.get()}, {root.get()},
             {unknown_critical_crl2.get()}, X509_V_FLAG_CRL_CHECK) !=
      X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION) {
    fprintf(stderr, "CRL with unknown critical extension (2) was accepted.\n");
    return false;
  }

  return true;
}

static bool TestPSS() {
  bssl::UniquePtr<X509> cert(CertFromPEM(kExamplePSSCert));
  if (!cert) {
    return false;
  }

  bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(cert.get()));
  if (!pkey) {
    return false;
  }

  if (!X509_verify(cert.get(), pkey.get())) {
    fprintf(stderr, "Could not verify certificate.\n");
    return false;
  }
  return true;
}

static bool TestBadPSSParameters() {
  bssl::UniquePtr<X509> cert(CertFromPEM(kBadPSSCertPEM));
  if (!cert) {
    return false;
  }

  bssl::UniquePtr<EVP_PKEY> pkey(X509_get_pubkey(cert.get()));
  if (!pkey) {
    return false;
  }

  if (X509_verify(cert.get(), pkey.get())) {
    fprintf(stderr, "Unexpectedly verified bad certificate.\n");
    return false;
  }
  ERR_clear_error();
  return true;
}

static bool SignatureRoundTrips(EVP_MD_CTX *md_ctx, EVP_PKEY *pkey) {
  // Make a certificate like signed with |md_ctx|'s settings.'
  bssl::UniquePtr<X509> cert(CertFromPEM(kLeafPEM));
  if (!cert || !X509_sign_ctx(cert.get(), md_ctx)) {
    return false;
  }

  // Ensure that |pkey| may still be used to verify the resulting signature. All
  // settings in |md_ctx| must have been serialized appropriately.
  return !!X509_verify(cert.get(), pkey);
}

static bool TestSignCtx() {
  bssl::UniquePtr<EVP_PKEY> pkey(PrivateKeyFromPEM(kRSAKey));
  if (!pkey) {
    return false;
  }

  // Test PKCS#1 v1.5.
  bssl::ScopedEVP_MD_CTX md_ctx;
  if (!EVP_DigestSignInit(md_ctx.get(), NULL, EVP_sha256(), NULL, pkey.get()) ||
      !SignatureRoundTrips(md_ctx.get(), pkey.get())) {
    fprintf(stderr, "RSA PKCS#1 with SHA-256 failed\n");
    return false;
  }

  // Test RSA-PSS with custom parameters.
  md_ctx.Reset();
  EVP_PKEY_CTX *pkey_ctx;
  if (!EVP_DigestSignInit(md_ctx.get(), &pkey_ctx, EVP_sha256(), NULL,
                          pkey.get()) ||
      !EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) ||
      !EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha512()) ||
      !SignatureRoundTrips(md_ctx.get(), pkey.get())) {
    fprintf(stderr, "RSA-PSS failed\n");
    return false;
  }

  return true;
}

static bool PEMToDER(bssl::UniquePtr<uint8_t> *out, size_t *out_len,
                     const char *pem) {
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, strlen(pem)));
  if (!bio) {
    return false;
  }

  char *name, *header;
  uint8_t *data;
  long data_len;
  if (!PEM_read_bio(bio.get(), &name, &header, &data, &data_len)) {
    fprintf(stderr, "failed to read PEM data.\n");
    return false;
  }
  OPENSSL_free(name);
  OPENSSL_free(header);

  out->reset(data);
  *out_len = data_len;

  return true;
}

static bool TestFromBuffer() {
  size_t data_len;
  bssl::UniquePtr<uint8_t> data;
  if (!PEMToDER(&data, &data_len, kRootCAPEM)) {
    return false;
  }

  bssl::UniquePtr<CRYPTO_BUFFER> buf(
      CRYPTO_BUFFER_new(data.get(), data_len, nullptr));
  if (!buf) {
    return false;
  }

  bssl::UniquePtr<X509> root(X509_parse_from_buffer(buf.get()));
  if (!root) {
    return false;
  }

  const uint8_t *enc_pointer = root->cert_info->enc.enc;
  const uint8_t *buf_pointer = CRYPTO_BUFFER_data(buf.get());
  if (enc_pointer < buf_pointer ||
      enc_pointer >= buf_pointer + CRYPTO_BUFFER_len(buf.get())) {
    fprintf(stderr, "TestFromBuffer: enc does not alias the buffer.\n");
    return false;
  }

  buf.reset();

  /* This ensures the X509 took a reference to |buf|, otherwise this will be a
   * reference to free memory and ASAN should notice. */
  if (enc_pointer[0] != CBS_ASN1_SEQUENCE) {
    fprintf(stderr, "TestFromBuffer: enc data is not a SEQUENCE.\n");
    return false;
  }

  return true;
}

static bool TestFromBufferTrailingData() {
  size_t data_len;
  bssl::UniquePtr<uint8_t> data;
  if (!PEMToDER(&data, &data_len, kRootCAPEM)) {
    return false;
  }

  std::unique_ptr<uint8_t[]> trailing_data(new uint8_t[data_len + 1]);
  OPENSSL_memcpy(trailing_data.get(), data.get(), data_len);

  bssl::UniquePtr<CRYPTO_BUFFER> buf_trailing_data(
      CRYPTO_BUFFER_new(trailing_data.get(), data_len + 1, nullptr));
  if (!buf_trailing_data) {
    return false;
  }

  bssl::UniquePtr<X509> root_trailing_data(
      X509_parse_from_buffer(buf_trailing_data.get()));
  if (root_trailing_data) {
    fprintf(stderr, "TestFromBuffer: trailing data was not rejected.\n");
    return false;
  }

  return true;
}

static bool TestFromBufferModified() {
  size_t data_len;
  bssl::UniquePtr<uint8_t> data;
  if (!PEMToDER(&data, &data_len, kRootCAPEM)) {
    return false;
  }

  bssl::UniquePtr<CRYPTO_BUFFER> buf(
      CRYPTO_BUFFER_new(data.get(), data_len, nullptr));
  if (!buf) {
    return false;
  }

  bssl::UniquePtr<X509> root(X509_parse_from_buffer(buf.get()));
  if (!root) {
    return false;
  }

  bssl::UniquePtr<ASN1_INTEGER> fourty_two(ASN1_INTEGER_new());
  ASN1_INTEGER_set(fourty_two.get(), 42);
  X509_set_serialNumber(root.get(), fourty_two.get());

  if (i2d_X509(root.get(), nullptr) != static_cast<long>(data_len)) {
    fprintf(stderr,
            "TestFromBufferModified: i2d_X509 gives different answer before "
            "marking as modified.\n");
    return false;
  }

  X509_CINF_set_modified(root->cert_info);

  if (i2d_X509(root.get(), nullptr) == static_cast<long>(data_len)) {
    fprintf(stderr,
            "TestFromBufferModified: i2d_X509 gives same answer after marking "
            "as modified.\n");
    return false;
  }

  return true;
}

static bool TestFromBufferReused() {
  size_t data_len;
  bssl::UniquePtr<uint8_t> data;
  if (!PEMToDER(&data, &data_len, kRootCAPEM)) {
    return false;
  }

  bssl::UniquePtr<CRYPTO_BUFFER> buf(
      CRYPTO_BUFFER_new(data.get(), data_len, nullptr));
  if (!buf) {
    return false;
  }

  bssl::UniquePtr<X509> root(X509_parse_from_buffer(buf.get()));
  if (!root) {
    return false;
  }

  size_t data2_len;
  bssl::UniquePtr<uint8_t> data2;
  if (!PEMToDER(&data2, &data2_len, kLeafPEM)) {
    return false;
  }

  X509 *x509p = root.get();
  const uint8_t *inp = data2.get();
  X509 *ret = d2i_X509(&x509p, &inp, data2_len);
  if (ret != root.get()) {
    fprintf(stderr,
            "TestFromBufferReused: d2i_X509 parsed into a different object.\n");
    return false;
  }

  if (root->buf != nullptr) {
    fprintf(stderr,
            "TestFromBufferReused: d2i_X509 didn't clear |buf| pointer.\n");
    return false;
  }

  // Free |data2| and ensure that |root| took its own copy. Otherwise the
  // following will trigger a use-after-free.
  data2.reset();

  uint8_t *i2d = nullptr;
  int i2d_len = i2d_X509(root.get(), &i2d);
  if (i2d_len < 0) {
    return false;
  }
  bssl::UniquePtr<uint8_t> i2d_storage(i2d);

  if (!PEMToDER(&data2, &data2_len, kLeafPEM)) {
    return false;
  }
  if (i2d_len != static_cast<long>(data2_len) ||
      OPENSSL_memcmp(data2.get(), i2d, i2d_len) != 0) {
    fprintf(stderr, "TestFromBufferReused: i2d gave wrong result.\n");
    return false;
  }

  if (root->buf != NULL) {
    fprintf(stderr, "TestFromBufferReused: X509.buf was not cleared.\n");
    return false;
  }

  return true;
}

static bool TestFailedParseFromBuffer() {
  static const uint8_t kNonsense[] = {1, 2, 3, 4, 5};

  bssl::UniquePtr<CRYPTO_BUFFER> buf(
      CRYPTO_BUFFER_new(kNonsense, sizeof(kNonsense), nullptr));
  if (!buf) {
    return false;
  }

  bssl::UniquePtr<X509> cert(X509_parse_from_buffer(buf.get()));
  if (cert) {
    fprintf(stderr, "Nonsense somehow parsed.\n");
    return false;
  }
  ERR_clear_error();

  // Test a buffer with trailing data.
  size_t data_len;
  bssl::UniquePtr<uint8_t> data;
  if (!PEMToDER(&data, &data_len, kRootCAPEM)) {
    return false;
  }

  std::unique_ptr<uint8_t[]> data_with_trailing_byte(new uint8_t[data_len + 1]);
  OPENSSL_memcpy(data_with_trailing_byte.get(), data.get(), data_len);
  data_with_trailing_byte[data_len] = 0;

  bssl::UniquePtr<CRYPTO_BUFFER> buf_with_trailing_byte(
      CRYPTO_BUFFER_new(data_with_trailing_byte.get(), data_len + 1, nullptr));
  if (!buf_with_trailing_byte) {
    return false;
  }

  bssl::UniquePtr<X509> root(
      X509_parse_from_buffer(buf_with_trailing_byte.get()));
  if (root) {
    fprintf(stderr, "Parsed buffer with trailing byte.\n");
    return false;
  }
  ERR_clear_error();

  return true;
}

static bool TestPrintUTCTIME() {
  static const struct {
    const char *val, *want;
  } asn1_utctime_tests[] = {
    {"", "Bad time value"},

    // Correct RFC 5280 form. Test years < 2000 and > 2000.
    {"090303125425Z", "Mar  3 12:54:25 2009 GMT"},
    {"900303125425Z", "Mar  3 12:54:25 1990 GMT"},
    {"000303125425Z", "Mar  3 12:54:25 2000 GMT"},

    // Correct form, bad values.
    {"000000000000Z", "Bad time value"},
    {"999999999999Z", "Bad time value"},

    // Missing components. Not legal RFC 5280, but permitted.
    {"090303125425", "Mar  3 12:54:25 2009"},
    {"9003031254", "Mar  3 12:54:00 1990"},
    {"9003031254Z", "Mar  3 12:54:00 1990 GMT"},

    // GENERALIZEDTIME confused for UTCTIME.
    {"20090303125425Z", "Bad time value"},

    // Legal ASN.1, but not legal RFC 5280.
    {"9003031254+0800", "Bad time value"},
    {"9003031254-0800", "Bad time value"},

    // Trailing garbage.
    {"9003031254Z ", "Bad time value"},
  };

  for (auto t : asn1_utctime_tests) {
    bssl::UniquePtr<ASN1_UTCTIME> tm(ASN1_UTCTIME_new());
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));

    // Use this instead of ASN1_UTCTIME_set() because some callers get
    // type-confused and pass ASN1_GENERALIZEDTIME to ASN1_UTCTIME_print().
    // ASN1_UTCTIME_set_string() is stricter, and would reject the inputs in
    // question.
    if (!ASN1_STRING_set(tm.get(), t.val, strlen(t.val))) {
      fprintf(stderr, "ASN1_STRING_set\n");
      return false;
    }
    const int ok = ASN1_UTCTIME_print(bio.get(), tm.get());

    const uint8_t *contents;
    size_t len;
    if (!BIO_mem_contents(bio.get(), &contents, &len)) {
      fprintf(stderr, "BIO_mem_contents\n");
      return false;
    }

    if (ok != (strcmp(t.want, "Bad time value") != 0)) {
      fprintf(stderr, "ASN1_UTCTIME_print(%s): bad return value\n", t.val);
      return false;
    }
    if (len != strlen(t.want) || memcmp(contents, t.want, len)) {
      fprintf(stderr, "ASN1_UTCTIME_print(%s): got %.*s, want %s\n", t.val,
              static_cast<int>(len),
              reinterpret_cast<const char *>(contents), t.want);
      return false;
    }
  }

  return true;
}

int main() {
  CRYPTO_library_init();

  if (!TestVerify() ||
      !TestCRL() ||
      !TestPSS() ||
      !TestBadPSSParameters() ||
      !TestSignCtx() ||
      !TestFromBuffer() ||
      !TestFromBufferTrailingData() ||
      !TestFromBufferModified() ||
      !TestFromBufferReused() ||
      !TestFailedParseFromBuffer() ||
      !TestPrintUTCTIME()) {
    return 1;
  }

  printf("PASS\n");
  return 0;
}
