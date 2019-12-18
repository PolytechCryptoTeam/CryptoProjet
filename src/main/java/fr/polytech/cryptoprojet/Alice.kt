package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger

class Alice(
	var paillier: Paillier
) {
	
	fun multi2(resultUxVy: Pair<BigInteger, BigInteger>) : BigInteger {
		// TODO (r + x)^(s + y)
		return paillier.encrypt(paillier.decryptToBigInteger(resultUxVy.first).multiply(paillier.decryptToBigInteger(resultUxVy.second)))
	}
}