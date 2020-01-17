package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger

class ProtocoleMultiplication(_paillier: Paillier) {
	val paillier=_paillier
	
	/**
	 * X and Y are encryption of the integer to multipl.
	 * Return encryption of the product og x and y
	 */
	fun secureMultiplication(X: BigInteger,Y:BigInteger): BigInteger{
		val alice = Alice(paillier)
		val bob=Bob(X,Y)
		
		val pair=bob.mult1((alice.paillier))
		
		val product = alice.mult2(pair)
		
		val XY = bob.mult3(alice.paillier, product)
		
		return XY
	}
	
}