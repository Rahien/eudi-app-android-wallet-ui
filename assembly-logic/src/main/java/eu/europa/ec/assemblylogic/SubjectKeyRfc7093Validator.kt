/*
 * Copyright (c) 2025 European Commission
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the European
 * Commission - subsequent versions of the EUPL (the "Licence"); You may not use this work
 * except in compliance with the Licence.
 *
 * You may obtain a copy of the Licence at:
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the Licence is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the Licence for the specific language
 * governing permissions and limitations under the Licence.
 */

package eu.europa.ec.assemblylogic

import android.util.Log
import eu.europa.ec.eudi.iso18013.transfer.readerauth.profile.ProfileValidation
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.security.MessageDigest
import java.security.cert.X509Certificate

class SubjectKeyRfc7093Validator : ProfileValidation {

    override fun validate(
        chain: List<X509Certificate>,
        trustCA: X509Certificate
    ): Boolean {

        require(chain.isNotEmpty())
        val cert = chain.first()

        // --- Extract SKI bytes from the certificate ---
        val skiExt = cert.getExtensionValue(Extension.subjectKeyIdentifier.id) ?: return false
        val ski = SubjectKeyIdentifier.getInstance(
            DEROctetString.getInstance(skiExt).octets
        ).keyIdentifier

        // --- Extract the subjectPublicKey BIT STRING ---
        val spki = SubjectPublicKeyInfo.getInstance(
            ASN1Sequence.getInstance(cert.publicKey.encoded)
        )
        val subjectPublicKeyBytes = spki.publicKeyData.bytes   // BIT STRING content

        // ----------------------------------------------------------
        // RFC 5280 classical SKI (SHA-1(publicKey BIT STRING))
        // ----------------------------------------------------------
        val sha1 = MessageDigest.getInstance("SHA-1")
            .digest(subjectPublicKeyBytes)

        // ----------------------------------------------------------
        // RFC 7093 Method 4:
        // SKI = first 160 bits of SHA-256(publicKey BIT STRING)
        // ----------------------------------------------------------
        val sha256Full = MessageDigest.getInstance("SHA-256")
            .digest(subjectPublicKeyBytes)

        val sha256Truncated = sha256Full.copyOfRange(0, 20)  // first 20 bytes

        // --- Match against either algorithm ---
        val matches =
            ski.contentEquals(sha1) ||
                    ski.contentEquals(sha256Truncated)

        Log.d("SKI-Validator", """
            SKI match:
              RFC5280_SHA1       = ${ski.contentEquals(sha1)}
              RFC7093_SHA256_160 = ${ski.contentEquals(sha256Truncated)}
        """.trimIndent())

        return matches
    }
}