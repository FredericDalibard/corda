package net.corda.node.services.identity

import net.corda.core.contracts.PartyAndReference
import net.corda.core.contracts.requireThat
import net.corda.core.crypto.CertificateAndKeyPair
import net.corda.core.crypto.subject
import net.corda.core.crypto.toStringShort
import net.corda.core.identity.AbstractParty
import net.corda.core.identity.AnonymousParty
import net.corda.core.identity.Party
import net.corda.core.identity.PartyAndCertificate
import net.corda.core.node.services.IdentityService
import net.corda.core.serialization.SingletonSerializeAsToken
import net.corda.core.utilities.loggerFor
import net.corda.core.utilities.trace
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import java.security.InvalidAlgorithmParameterException
import java.security.PublicKey
import java.security.cert.*
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import javax.annotation.concurrent.ThreadSafe

/**
 * Simple identity service which caches parties and provides functionality for efficient lookup.
 *
 * @param identities initial set of identities for the service, typically only used for unit tests.
 * @param certPaths initial set of certificate paths for the service, typically only used for unit tests.
 */
@ThreadSafe
class InMemoryIdentityService(identities: Iterable<Party> = emptySet(),
                              certPaths: Map<AnonymousParty, CertPath> = emptyMap(),
                              val networkRoot: CertificateAndKeyPair?) : SingletonSerializeAsToken(), IdentityService {
    companion object {
        private val log = loggerFor<InMemoryIdentityService>()
    }

    private val trustAnchor: TrustAnchor?
    private val keyToParties = ConcurrentHashMap<PublicKey, Party>()
    private val principalToParties = ConcurrentHashMap<X500Name, Party>()
    private val partyToPath = ConcurrentHashMap<AbstractParty, CertPath>()

    init {
        trustAnchor = if (networkRoot != null) {
            val rootCert = JcaX509CertificateConverter().getCertificate(networkRoot.certificate)
            TrustAnchor(rootCert, null)
        } else {
            null
        }
        keyToParties.putAll(identities.associateBy { it.owningKey } )
        principalToParties.putAll(identities.associateBy { it.name })
        partyToPath.putAll(certPaths)
    }

    // TODO: Check the validation logic
    @Throws(CertificateExpiredException::class, CertificateNotYetValidException::class, InvalidAlgorithmParameterException::class)
    override fun registerIdentity(party: PartyAndCertificate) {
        require(party.certPath.certificates.isNotEmpty()) { "Certificate path must contain at least one certificate" }
        // Validate the chain first, before we do anything clever with it
        val validatorParameters = if (trustAnchor != null) {
            PKIXParameters(setOf(trustAnchor))
        } else {
            // TODO: We should always require a full chain back to a trust anchor, but until we have a network
            // trust anchor everywhere, this will have to do.
            val converter = JcaX509CertificateConverter()
            PKIXParameters(setOf(TrustAnchor(converter.getCertificate(party.certificate), null)))
        }
        val validator = CertPathValidator.getInstance("PKIX")
        validatorParameters.isRevocationEnabled = false
        // TODO: val result = validator.validate(party.certPath, validatorParameters) as PKIXCertPathValidatorResult
        // require(trustAnchor == null || result.trustAnchor == trustAnchor)
        // require(result.publicKey == party.owningKey) { "Certificate path validation must end at transaction key ${anonymousParty.owningKey.toStringShort()}, found ${result.publicKey.toStringShort()}" }

        log.trace { "Registering identity $party" }
        require(Arrays.equals(party.certificate.subjectPublicKeyInfo.encoded, party.owningKey.encoded)) { "Party certificate must end with party's public key" }

        partyToPath[party] = party.certPath
        keyToParties[party.owningKey] = party
        principalToParties[party.name] = party
    }

    @Throws(CertificateExpiredException::class, CertificateNotYetValidException::class, InvalidAlgorithmParameterException::class)
    override fun registerAnonymousIdentity(anonymousParty: AnonymousParty, fullParty: PartyAndCertificate, path: CertPath) {
        require(path.certificates.isNotEmpty()) { "Certificate path must contain at least one certificate" }
        // Validate the chain first, before we do anything clever with it
        val validator = CertPathValidator.getInstance("PKIX")
        val validatorParameters = if (trustAnchor != null) {
            PKIXParameters(setOf(trustAnchor))
        } else {
            // TODO: We should always require a full chain back to a trust anchor, but until we have a network
            // trust anchor everywhere, this will have to do.
            val converter = JcaX509CertificateConverter()
            PKIXParameters(setOf(TrustAnchor(converter.getCertificate(fullParty.certificate), null)))
        }
        validatorParameters.isRevocationEnabled = false
        val result = validator.validate(path, validatorParameters) as PKIXCertPathValidatorResult
        val subjectCertificate = path.certificates.first()
        require(trustAnchor == null || result.trustAnchor == trustAnchor)
        require(result.publicKey == anonymousParty.owningKey) { "Certificate path validation must end at transaction key ${anonymousParty.owningKey.toStringShort()}, found ${result.publicKey.toStringShort()}" }
        require(subjectCertificate is X509Certificate && subjectCertificate.subject == fullParty.name) { "Subject of the transaction certificate must match the well known identity" }

        log.trace { "Registering identity $fullParty" }

        partyToPath[anonymousParty] = path
        keyToParties[anonymousParty.owningKey] = fullParty
        principalToParties[fullParty.name] = fullParty
    }

    // We give the caller a copy of the data set to avoid any locking problems
    override fun getAllIdentities(): Iterable<Party> = ArrayList(keyToParties.values)

    override fun partyFromKey(key: PublicKey): Party? = keyToParties[key]
    @Deprecated("Use partyFromX500Name")
    override fun partyFromName(name: String): Party? = principalToParties[X500Name(name)]
    override fun partyFromX500Name(principal: X500Name): Party? = principalToParties[principal]
    override fun partyFromAnonymous(party: AbstractParty): Party? {
        return if (party is Party) {
            party
        } else {
            partyFromKey(party.owningKey)
        }
    }
    override fun partyFromAnonymous(partyRef: PartyAndReference) = partyFromAnonymous(partyRef.party)
    override fun requirePartyFromAnonymous(party: AbstractParty): Party {
        return partyFromAnonymous(party) ?: throw IllegalStateException("Could not deanonymise party ${party.owningKey.toStringShort()}")
    }

    @Throws(IdentityService.UnknownAnonymousPartyException::class)
    override fun assertOwnership(party: Party, anonymousParty: AnonymousParty) {
        val path = partyToPath[anonymousParty] ?: throw IdentityService.UnknownAnonymousPartyException("Unknown anonymous party ${anonymousParty.owningKey.toStringShort()}")
        val target = path.certificates.last() as X509Certificate
        requireThat {
            "Certificate path ends with \"${target.issuerX500Principal}\" expected \"${party.name}\"" using (X500Name(target.subjectX500Principal.name) == party.name)
            "Certificate path ends with correct public key" using (target.publicKey == anonymousParty.owningKey)
        }
        // Verify there's a previous certificate in the path, which matches
        val root = path.certificates.first() as X509Certificate
        require(X500Name(root.issuerX500Principal.name) == party.name) { "Certificate path starts with \"${root.issuerX500Principal}\" expected \"${party.name}\"" }
    }

    override fun pathForAnonymous(anonymousParty: AnonymousParty): CertPath? = partyToPath[anonymousParty]
}
