using CertiPay.Common.Testing;
using NUnit.Framework;
using System;
using System.IO;

namespace CertiPay.Common.Encryption.Tests
{
    public class PGPUtilitiesTest
    {
        private const String passphrase = "test";

        private const String pubKey = @"-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: BCPG C# v1.6.1.0

mQENBFa7mNABCACaQ3ZF7OS5PO1Bo09uIjcOsLbDcY/qMwdgHHP7kpZFH9H6yiHP
8XLHAiieBeYG1MgG8aEo2wTyi/JIdVZxHSTdDahy7+oC1MVSKiP8naF7Qz8/MJrn
JXKqaT6s5IDMyGXl8AtJ+UUlk/Q5K8eWd6QzqkATooXaLkCl4LSvCLZj5qmM4Qw1
Y0lM1j2uX/isZMmydk62OvVjehOfmwR4RBjoi1EVhz49DHRvTTLE1rSBVN55OeNq
CNguMOhMm9bIEKSluE3Eh4eEqys/FXV1TQ89SpWv5fF8OVDK+81q5oCCeArkg+MT
tzrYmLUJ8vTqKOpCZllSKWENddvXCYcWR5ZbABEBAAG0FG13YWduZXJAY2VydGlw
YXkuY29tiQEcBBABAgAGBQJWu5jQAAoJEFZ8uE5ErDy/ogQH/3nXyqP2f2gU/IcV
jSXDmsz1w2jcgCLoD8OAkeRrSI/LzIlpZMf0OnHyaJrTOAAIBom50gcYQ4jfBBDD
9njj/t3Yecu/DtmCvm8vCP+LuYLcPbRoVuECk4G9MHIn0E5EpqgEWxDaSv+lkC96
FE4ZwBaAQyaqvApp1gzqT8rY3V5ht4ejgBckzt0diVZJdMGg2cs/2Zo9fMrHiKd8
ovWO9UB0JHtNS32my5gzN6KDPoQ65A+dMVLj/UQ6D25tsKVbX13wHJsbElanXytX
aBzLmlOpHU+3yox98ZyA6+Re1roXD4BDgcoFFihszjJIMoj53cilTRqF+ccl91Fn
lmpEwxw=
=6Qb5
-----END PGP PUBLIC KEY BLOCK-----
";

        private const String privateKey = @"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: BCPG C# v1.6.1.0

lQOsBFa7mNABCACaQ3ZF7OS5PO1Bo09uIjcOsLbDcY/qMwdgHHP7kpZFH9H6yiHP
8XLHAiieBeYG1MgG8aEo2wTyi/JIdVZxHSTdDahy7+oC1MVSKiP8naF7Qz8/MJrn
JXKqaT6s5IDMyGXl8AtJ+UUlk/Q5K8eWd6QzqkATooXaLkCl4LSvCLZj5qmM4Qw1
Y0lM1j2uX/isZMmydk62OvVjehOfmwR4RBjoi1EVhz49DHRvTTLE1rSBVN55OeNq
CNguMOhMm9bIEKSluE3Eh4eEqys/FXV1TQ89SpWv5fF8OVDK+81q5oCCeArkg+MT
tzrYmLUJ8vTqKOpCZllSKWENddvXCYcWR5ZbABEBAAH/AwMC/FU8Xg8F2Mxg/9G4
VHiqNv+1GKvfxlGCwcLz8lIdzGG2ZN/yUP9cswZWQ7NJouQVsw58nybR5vf2psZF
ThIM31BwW9HcOzYZqoPFzUrivijvAMuLKXb71/Z8oOFtl2PzPBe7We85usu52fUh
hS+vD+3vew5WJYaMUnQYxSjWJHkM70JrVb0hvMaxnmp8XMXxKU3OSKkJBRlalfHl
iGwNHoVbkcVtBGio+g2LMp/nJBWlE7ziJP+19hWKBeEMnjZDsAKpZPrr7x/WG61y
vLEsos/sRMgPL+FBfHa5dawdvmSSGitu6prwrSycx1DpWDQMDTRQw+NDOQQ9zauz
7S+FqMVvQ/tUTqdYc9uvGbEYFGardnPrGWSfDBRW28z1uBS9ZTcJ0IJpfALTbvbH
kAeqX6FhRDgExAzKKZ7MZ3nFdOq2fK4FKAH7yFhuUpN9Qpbx0GdabvzSNg2bm4uy
igSKYVtn9zfNzM97fLRPPuJZZf5aSjRz6ruWFgYCbpBfwTbQO9yTdTgvUIsTuQ/W
PTPwrfXDIA+5vlGasCGCCFg0b9wIuGRYq1mIx+JEk8qP5qla2iduFdFe+/7rfALH
37N2PfLtogXZRfOF38AlBs6ZQ5TLdjWQgcAhNI1qns/jgnANGwvOyWyT62DRqgxH
KfMUd2NPWM0dTaJFSHPx5KUJu9kakgTql8R8bVMK6eJh56PSt776LwKxav+OcUj2
4G8Bd6UYImyEe6kUhMaoZ4wePfw0IG3GX/OaCPmJZZs4YJf4W7hg0zKRYBe8BC6H
LDoX0qr9MguzEmOSTdml+EQPGZGqucBuvvgOAFN0vNEcLDk8fkIDFQsC22qjMO7Z
2yMGoGff9RwW4h8m5EvBwNeTvux5f6XV1AfN8E8KTbQUbXdhZ25lckBjZXJ0aXBh
eS5jb22JARwEEAECAAYFAla7mNAACgkQVny4TkSsPL+iBAf/edfKo/Z/aBT8hxWN
JcOazPXDaNyAIugPw4CR5GtIj8vMiWlkx/Q6cfJomtM4AAgGibnSBxhDiN8EEMP2
eOP+3dh5y78O2YK+by8I/4u5gtw9tGhW4QKTgb0wcifQTkSmqARbENpK/6WQL3oU
ThnAFoBDJqq8CmnWDOpPytjdXmG3h6OAFyTO3R2JVkl0waDZyz/Zmj18yseIp3yi
9Y71QHQke01LfabLmDM3ooM+hDrkD50xUuP9RDoPbm2wpVtfXfAcmxsSVqdfK1do
HMuaU6kdT7fKjH3xnIDr5F7WuhcPgEOBygUWKGzOMkgyiPndyKVNGoX5xyX3UWeW
akTDHA==
=97nn
-----END PGP PRIVATE KEY BLOCK-----
";

        [Test, Unit]
        [TestCase("this is my test phrase!")]
        [TestCase("I can't believe it's not butter!")]
        [TestCase("abcjwnljkgnoingk54jngkj43n98thtion34klgnerkolnvION!OInolgkn34lkgn34oklngi34hngio435n")]
        public void Verify_Encryption_Output(String input)
        {
            String cryptoString = String.Empty;

            using (var stream = pubKey.Streamify())
            {
                var key = stream.ImportPublicKey();

                using (var clearStream = input.Streamify())
                using (var cryptoStream = new MemoryStream())
                {
                    clearStream.PgpEncrypt(cryptoStream, key);

                    cryptoStream.Position = 0;

                    cryptoString = cryptoStream.Stringify();
                }
            }

            using (var stream = cryptoString.Streamify())
            {
                using (var clearStream = stream.PgpDecrypt(privateKey, passphrase))
                {
                    Assert.AreEqual(input, clearStream.Stringify());
                }
            }
        }
    }
}