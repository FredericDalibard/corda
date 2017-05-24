package net.corda.core.node

import net.corda.core.contracts.ContractState
import net.corda.core.contracts.DummyContract
import net.corda.core.identity.Party
import net.corda.core.serialization.deserialize
import net.corda.core.serialization.serialize
import net.corda.testing.node.MockNetwork
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals

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
        val ptx = DummyContract.generateInitial(1337, notary, a.services.myInfo.legalIdentity.ref(1))
        val wtx = ptx.toWireTransaction()
        val actual = wtx.serialized.deserialize()
        assertEquals(wtx, actual)
        assertEquals(wtx.merkleTree, actual.merkleTree)
        assertEquals(wtx.id, actual.id)
        val stx = a.services.signInitialTransaction(ptx)
        stx.verifySignatures()
    }
}