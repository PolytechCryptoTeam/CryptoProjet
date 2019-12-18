package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Cryptaception
import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger
import java.util.*

class Bob(
	var X: BigInteger,
	var Y: BigInteger
) {
	
	var u = BigInteger.ZERO
	var v = BigInteger.ZERO
	
	fun Paillier.decryptPlus(encryptedBigInteger: BigInteger): Pair<BigInteger, BigInteger> {
		// r = (M mod n)^rho
		val r = encryptedBigInteger.modPow(secretKey, publicKey)
		// m = ((M * r^(-n) mod n²) - 1)/n
		val m = (encryptedBigInteger.multiply(r.modPow(publicKey, publicKey.pow(2)).modInverse(publicKey.pow(2))))
			.mod(publicKey.pow(2)).subtract(BigInteger.ONE).divide(publicKey)
		return Pair(m, r)
	}
	
	fun mult1(paillier: Paillier): Pair<BigInteger, BigInteger> {
		while (u == v || u == BigInteger.ZERO || v == BigInteger.ZERO) {
			u = BigInteger(Cryptaception.DEFAULT_KEY_SIZE_BITS, Random()).mod(paillier.publicKey)
			v = BigInteger(Cryptaception.DEFAULT_KEY_SIZE_BITS, Random()).mod(paillier.publicKey)
		}
		return Pair(paillier.encrypt(u).multiply(X), paillier.encrypt(v).multiply(Y))
	}
	
	fun multi3(paillier: Paillier, factor: BigInteger): BigInteger {
		// TODO (Use homomoprhie https://en.wikipedia.org/wiki/Paillier_cryptosystem)
		return BigInteger.ZERO
	}
}