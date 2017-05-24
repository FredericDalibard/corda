package net.corda.core.node

import net.corda.core.contracts.DummyContract
import net.corda.core.identity.Party
import net.corda.testing.node.MockNetwork
import org.junit.Before
import org.junit.Test

/**
 * Tests for functions in the standard service hub.
 */
class ServiceHubTests {
    lateinit var mockNet: MockNetwork
    lateinit var a: MockNetwork.MockNode
    lateinit var notary: Party

    @Before
    fun setup() {
        mockNet = MockNetwork()
        val nodes = mockNet.createSomeNodes(2)
        a = nodes.partyNodes[1]
        notary = nodes.notaryNode.info.notaryIdentity
        mockNet.runNetwork()
    }


    @Test
    fun `sign initial transaction`() {
        val onePartyDummyContract = DummyContract.generateInitial(1337, notary, a.services.myInfo.legalIdentity.ref(1))
        val ptx = a.services.signInitialTransaction(onePartyDummyContract)
        ptx.verifySignatures()
    }
}