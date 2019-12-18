package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Cryptaception
import fr.polytech.berger.cryptaception.Paillier
import main.ExtendsPaillier.PaillierExtended
import java.math.BigInteger
import java.util.*

/**
 * doesn't have the private key
 */
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
	
	fun mult1(paillier: PaillierExtended): Pair<BigInteger, BigInteger> {
		while (u == v || u == BigInteger.ZERO || v == BigInteger.ZERO) {
			u = BigInteger(Cryptaception.DEFAULT_KEY_SIZE_BITS, Random()).mod(paillier.publicKey)
			v = BigInteger(Cryptaception.DEFAULT_KEY_SIZE_BITS, Random()).mod(paillier.publicKey)
		}
		return Pair(paillier.encrypt(u).multiply(X), paillier.encrypt(v).multiply(Y))
	}
	
	fun multi3(paillier: PaillierExtended, factor: BigInteger): BigInteger {
		// TODO (Use homomoprhie https://en.wikipedia.org/wiki/Paillier_cryptosystem)
		val negativeS=u.multiply(BigInteger.valueOf(-1))
		val negativeR=v.multiply(BigInteger.valueOf(-1))
		val encryptednegativeSX=paillier.homomorphicMultiplication(X,negativeS)
		val encryptednegativeRY=paillier.homomorphicMultiplication(Y,negativeR)
		val negativeRS=negativeR.multiply(u)
		val encryptedNegativeRS=paillier.encrypt(negativeRS)
		
		val sum1=paillier.homomorphicAddition(factor,encryptednegativeSX)
		val sum2=paillier.homomorphicAddition(sum1,encryptednegativeRY)
		val sum3=paillier.homomorphicAddition(sum2,encryptedNegativeRS)
		
		return sum3
	}
}