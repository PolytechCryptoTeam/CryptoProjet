package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger

open class ProtocoleMultiplication(val paillier: Paillier) {
	
	/**
	 * X and Y are encryption of the integer to multiply.
	 * Return encryption of the product of x and y.
	 */
	open fun secureMultiplication(X: BigInteger,Y:BigInteger): BigInteger{
		val alice = Alice(paillier)
		val bob=Bob(X,Y)
		
		val pair=bob.mult1((alice.paillier))
		
		val product = alice.mult2(pair)
		
		val XY = bob.mult3(alice.paillier, product)
		
		return XY
	}
	
}