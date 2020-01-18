package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Cryptaception
import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger
import java.util.*

class Alice(
	var paillier: Paillier
) {
	private var _alpha: BigInteger = BigInteger.ZERO // MultiProof
	private var _beta: BigInteger = BigInteger.ZERO // MultiProof
	private var _gamma: BigInteger = BigInteger.ZERO // MultiProof
	private var _delta: BigInteger = BigInteger.ZERO // MultiProof
	private var _pi: BigInteger = BigInteger.ZERO // MultiProof
	
	val alpha: BigInteger
		get() = _alpha
	
	val beta: BigInteger
		get() = _beta
	
	val gamma: BigInteger
		get() = _gamma
	
	val delta: BigInteger
		get() = _delta
	
	val pi: BigInteger
		get() = _pi
	
	fun Paillier.decryptPlus(encryptedBigInteger: BigInteger): Pair<BigInteger, BigInteger> {
		// r = (M mod n)^rho
		val r = encryptedBigInteger.modPow(secretKey, publicKey)
		// m = ((M * r^(-n) mod n²) - 1)/n
		val m = (encryptedBigInteger.multiply(r.modPow(publicKey, publicKey.pow(2)).modInverse(publicKey.pow(2))))
			.mod(publicKey.pow(2)).subtract(BigInteger.ONE).divide(publicKey)
		return Pair(m, r)
	}
	
	fun mult2(resultUxVy: Pair<BigInteger, BigInteger>) : BigInteger {
		// (E(u) * X)^Decrypt(E(v) * Y) (⟺ (u + x) * (v + y))
		return resultUxVy.first.modPow(paillier.decryptToBigInteger(resultUxVy.second), paillier.publicKey.pow(2))
	}
	
	fun chooseMultiProofEncryption(random: Random = Random()) {
		_alpha = BigInteger.probablePrime(Cryptaception.DEFAULT_KEY_SIZE_BITS, random)
		_beta = BigInteger.probablePrime(Cryptaception.DEFAULT_KEY_SIZE_BITS, random)
		
		// γ = α β mod n
		_gamma = _alpha.multiply(_beta).mod(paillier.publicKey)
		
		_delta = BigInteger.probablePrime(Cryptaception.DEFAULT_KEY_SIZE_BITS, random)
		
		// π = δ β mod n
		_pi = _delta.multiply(_beta).mod(paillier.publicKey)
	}
	
	fun decryptAlphaBetaGamma(e: BigInteger): Pair<Pair<BigInteger, BigInteger>, Pair<BigInteger, BigInteger>> {
		val nSquared = paillier.publicKey.pow(2)
		val ar = paillier.decryptPlus(_alpha.modPow(e, nSquared).multiply(_delta).mod(paillier.publicKey.pow(2)))
		val arPrime = paillier.decryptPlus(_beta.modPow(_alpha, nSquared).multiply(_pi.modInverse(nSquared)).multiply(_gamma.modPow(e.negate(), nSquared)).mod(paillier.publicKey.pow(2)))
		return Pair(ar, arPrime)
	}
}