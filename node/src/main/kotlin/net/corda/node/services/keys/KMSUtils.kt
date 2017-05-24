package net.corda.node.services.keys

import net.corda.core.crypto.CertificateType
import net.corda.core.crypto.ContentSignerBuilder
import net.corda.core.crypto.Crypto
import net.corda.core.crypto.X509Utilities
import net.corda.core.identity.AnonymousParty
import net.corda.core.identity.PartyAndCertificate
import net.corda.core.node.services.IdentityService
import net.corda.core.node.services.KeyManagementService
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.operator.ContentSigner
import java.security.KeyPair
import java.security.Security
import java.security.cert.CertPath
import java.security.cert.X509Certificate
import java.time.Duration
import java.util.*

/**
 * Generates a new random [KeyPair], adds it to the internal key storage, then generates a corresponding
 * [X509Certificate] and adds it to the identity service.
 *
 * @param keyManagementService key service to use when generating the new key.
 * @param identityService issuer service to use when registering the certificate.
 * @param issuer issuer to generate a key and certificate for. Must be an identity this node has the private key for.
 * @param revocationEnabled whether to check revocation status of certificates in the certificate path.
 * @return X.509 certificate and path to the trust root.
 */
fun freshKeyAndCert(keyManagementService: KeyManagementService,
                    identityService: IdentityService,
                    issuer: PartyAndCertificate,
                    revocationEnabled: Boolean = false): Pair<X509CertificateHolder, CertPath> {
    val subjectPublicKey = keyManagementService.freshKey()
    val issuerCertificate = issuer.certificate
    val signer: ContentSigner = keyManagementService.getSigner(issuer.owningKey)
    val window = X509Utilities.getCertificateValidityWindow(Duration.ZERO, Duration.ofDays(10 * 365), issuerCertificate)
    val ourCertificate = Crypto.createCertificate(CertificateType.IDENTITY, issuerCertificate.subject, signer, issuer.name, subjectPublicKey, window)
    val actualPublicKey = Crypto.decodePublicKey(ourCertificate.subjectPublicKeyInfo.encoded)
    require(subjectPublicKey == actualPublicKey)
    val ourCertPath = X509Utilities.createCertificatePath(issuerCertificate, ourCertificate, revocationEnabled = revocationEnabled)
    require(Arrays.equals(ourCertificate.subjectPublicKeyInfo.encoded, subjectPublicKey.encoded))
    identityService.registerAnonymousIdentity(AnonymousParty(subjectPublicKey),
            issuer,
            ourCertPath)
    return Pair(issuerCertificate, ourCertPath)
}

fun getSigner(issuerKeyPair: KeyPair): ContentSigner {
    val signatureScheme = Crypto.findSignatureScheme(issuerKeyPair.private)
    val provider = Security.getProvider(signatureScheme.providerName)
    return ContentSignerBuilder.build(signatureScheme, issuerKeyPair.private, provider)
}