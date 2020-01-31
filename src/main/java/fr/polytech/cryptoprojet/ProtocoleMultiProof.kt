package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger
import kotlin.test.assertTrue

class ProtocoleMultiProof(val paillier: Paillier) {
	
	fun secureMultiplication(X: BigInteger, Y: BigInteger): BigInteger {
		val alice = Alice(paillier)
		alice.chooseMultiProofEncryption()
		val bob=Bob(X, Y, alice.delta, alice.pi)
		
		val pair=bob.mult1(alice.paillier)
		
		val product = alice.mult2(pair)
		
		alice.chooseMultiProofEncryption()
		
		// Alice envoie α, β, γ, δ et π à Bob
		bob.alpha = alice.alpha
		bob.beta = alice.beta
		bob.gamma = alice.gamma
		bob.delta = alice.delta
		bob.pi = alice.pi
		
		// Bob choisit e
		bob.chooseE(paillier.publicKey)
		val arAPrimeRPrime = alice.decryptAlphaBetaGamma(bob.e)
		
		// Bob vérifie
		assertTrue(bob.checkEncryption(arAPrimeRPrime, paillier.publicKey))
		
		val XY = bob.mult3(alice.paillier, product)
		
		return XY
	}
}