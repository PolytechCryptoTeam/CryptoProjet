package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger

class Alice(
	var paillier: Paillier
) {
	
	fun mult2(resultUxVy: Pair<BigInteger, BigInteger>) : BigInteger {
		// (E(u) * X)^Decrypt(E(v) * Y) (⟺ (u + x) * (v + y))
		return resultUxVy.first.modPow(paillier.decryptToBigInteger(resultUxVy.second), paillier.publicKey.pow(2))
	}
}