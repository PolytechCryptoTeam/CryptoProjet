package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import main.ExtendsPaillier.PaillierExtended
import java.math.BigInteger

/**
 * has the private key
 */
class Alice(
	var paillier: PaillierExtended
) {
	
	fun multi2(resultUxVy: Pair<BigInteger, BigInteger>) : BigInteger {
		// TODO (r + x)^(s + y)
		return paillier.encrypt(paillier.decryptToBigInteger(resultUxVy.first).multiply(paillier.decryptToBigInteger(resultUxVy.second)))
	}
}