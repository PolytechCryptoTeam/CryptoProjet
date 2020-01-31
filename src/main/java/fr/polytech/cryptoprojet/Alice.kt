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
	
	/**
	 * Return (u + x) * (v + y).
	 * @param resultUxVy Pair containing (u + x) and (v + y).
	 * @param corruptScenario Alice is not always trustworthy. Put `corruptScenario` to `true`, and the return reuslt
	 * will be wrong.
	 */
	fun mult2(resultUxVy: Pair<BigInteger, BigInteger>, corruptScenario: Boolean = false) : BigInteger {
		return if (!corruptScenario) {
			// (E(u) * X)^Decrypt(E(v) * Y) mod n² (⟺ (u + x) * (v + y))
			resultUxVy.first.modPow(paillier.decryptToBigInteger(resultUxVy.second), paillier.publicKey.pow(2))
		} else {
			// (E(u) * X) * (E(v) * Y) mod n² (⟺ (u + x) + (v + y))
			resultUxVy.first.multiply(resultUxVy.second).mod(paillier.publicKey.pow(2));
		}
	}
	
	fun Multi1(resultUxVy: Pair<BigInteger, BigInteger>? = null, random: Random = Random()) {
		if (resultUxVy == null) {
			_alpha = paillier.encrypt(BigInteger.probablePrime(Cryptaception.DEFAULT_KEY_SIZE_BITS, random))
			_beta = paillier.encrypt(BigInteger.probablePrime(Cryptaception.DEFAULT_KEY_SIZE_BITS, random))
		}
		else {
			_alpha = resultUxVy.first
			_beta = resultUxVy.second
		}
		
		// [γ] = [α]^β mod n² ⟺ γ = α β mod n
		_gamma = _alpha.modPow(paillier.decryptToBigInteger(_beta), paillier.publicKey.pow(2))
		assert(paillier.decryptToBigInteger(_gamma) == paillier.decryptToBigInteger(_alpha).multiply(paillier.decryptToBigInteger(_beta)).mod(paillier.publicKey))
		
		// δ ∈ ℤ/nℤ
		_delta = paillier.encrypt(BigInteger.probablePrime(Cryptaception.DEFAULT_KEY_SIZE_BITS, random)).mod(paillier.publicKey)
		
		// [π] = [δ]^β mod n² ⟺ π = δ β mod n
		_pi = _delta.modPow(paillier.decryptToBigInteger(_beta), paillier.publicKey.pow(2))
		assert(paillier.decryptToBigInteger(_pi) == paillier.decryptToBigInteger(_delta).multiply(paillier.decryptToBigInteger(_beta)).mod(paillier.publicKey))
	}
	
	fun Multi3(e: BigInteger): Pair<Pair<BigInteger, BigInteger>, Pair<BigInteger, BigInteger>> {
		// n²
		val nSquared = paillier.publicKey.pow(2)
		// (a, r) = DecryptPlus([α]ᵉ * [δ] mod n²)
		val ar = paillier.decryptPlus((_alpha.modPow(e, nSquared)).multiply(_delta).mod(nSquared))
		// (a', r') = DecryptPlus([β]ᵃ * [π]⁻¹ * [γ]⁻ᵉ mod n²)
		val arPrime = paillier.decryptPlus((_beta.modPow(ar.first, nSquared)).multiply(_pi.modInverse(nSquared)).multiply((_gamma.modPow(e, nSquared)).modInverse(nSquared)).mod(nSquared))
		return Pair(ar, arPrime)
	}
}