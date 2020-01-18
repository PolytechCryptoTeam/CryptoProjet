package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger

class ProtocoleMultiProof(val paillier: Paillier) {
	
	fun secureMultiplication(X: BigInteger, Y: BigInteger): BigInteger {
		val alice = Alice(paillier)
		alice.chooseMultiProofEncryption()
		val bob=Bob(X, Y, alice.delta, alice.pi)
		
		val pair=bob.mult1(alice.paillier)
		
		val product = alice.mult2(pair)
		
		val XY = bob.mult3(alice.paillier, product)
		
		return XY
	}
}