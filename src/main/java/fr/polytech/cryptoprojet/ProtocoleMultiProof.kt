package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger
import kotlin.test.assertTrue

open class ProtocoleMultiProof(paillier: Paillier) : ProtocoleMultiplication(paillier) {
	
	override fun secureMultiplication(X: BigInteger, Y: BigInteger): BigInteger {
		val alice = Alice(paillier)
		val bob=Bob(X, Y)
		
		val pair=bob.mult1(alice.paillier)
		
		val product = alice.mult2(pair, corruptScenario = false)
		
		alice.Multi1(pair)
		
		// Alice envoie α, β, γ, δ et π à Bob
		bob.alpha = alice.alpha
		bob.beta = alice.beta
		bob.gamma = alice.gamma
		bob.delta = alice.delta
		bob.pi = alice.pi
		
		// Bob choisit e
		bob.Multi2(paillier.publicKey)
		val arAPrimeRPrime = alice.Multi3(bob.e)
		
		// Bob vérifie
		assertTrue(bob.Multi4(arAPrimeRPrime, paillier.publicKey))
		
		val XY = bob.mult3(alice.paillier, product)
		
		return XY
	}
}