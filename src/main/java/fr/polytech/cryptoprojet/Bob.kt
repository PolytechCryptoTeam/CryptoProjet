package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Cryptaception
import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger
import java.util.*

class Bob(
	var X: BigInteger,
	var Y: BigInteger,
	var alpha: BigInteger = BigInteger.ZERO, // MultiProof
	var beta: BigInteger = BigInteger.ZERO, // MultiProof
	var gamma: BigInteger = BigInteger.ZERO, // MultiProof
	var delta: BigInteger = BigInteger.ZERO, // MultiProof
	var pi: BigInteger = BigInteger.ZERO // MultiProof
) {
	
	var u = BigInteger.ZERO
	var v = BigInteger.ZERO
	var e = BigInteger.ZERO // MultiProof
	
	fun mult1(paillier: Paillier): Pair<BigInteger, BigInteger> {
		// Choose two scalars u and v randomly
		while (u == v || u == BigInteger.ZERO || v == BigInteger.ZERO) {
			u = BigInteger(Cryptaception.DEFAULT_KEY_SIZE_BITS, Random()).mod(paillier.publicKey)
			v = BigInteger(Cryptaception.DEFAULT_KEY_SIZE_BITS, Random()).mod(paillier.publicKey)
		}
		// E(u) * X, E(v) * Y (⟺ u + x, v + y)
		return Pair(paillier.encrypt(u).multiply(X), paillier.encrypt(v).multiply(Y))
	}
	
	fun mult3(paillier: Paillier, factor: BigInteger): BigInteger {
		// (E(u) * X)^Decrypt(E(v) * Y) - (X^v mod n²) - (Y^u mod n²) - (u * v)
		// ⟺ (u + x) * (v + y) - vx - uy - uv
		// ⟺ x * y
		return factor
			.multiply(X.modPow(v, paillier.publicKey.pow(2)).modInverse(paillier.publicKey.pow(2)))
			.multiply(Y.modPow(u, paillier.publicKey.pow(2)).modInverse(paillier.publicKey.pow(2)))
			.multiply(paillier.encrypt(u).modPow(v, paillier.publicKey.pow(2)).modInverse(paillier.publicKey.pow(2)))
	}
	
	fun chooseE(n: BigInteger, random: Random = Random()): BigInteger {
		e = BigInteger.probablePrime(Cryptaception.DEFAULT_KEY_SIZE_BITS, random)
		return e
	}
	
	fun checkEncryption(ar: Pair<BigInteger, BigInteger>, arPrime: Pair<BigInteger, BigInteger>, n: BigInteger): Boolean {
		val a = ar.first
		val r = ar.second
		val aPrime = arPrime.first
		val rPrime = arPrime.second
		val nSquared = n.pow(2)
		
		// Check 1
		val lhs1 = (a.multiply(n).add(BigInteger.ONE)).multiply(r.mod(n))
		val rhs1 = alpha.modPow(e, nSquared).multiply(delta).mod(nSquared)
		
		if (rhs1 != lhs1)
			return false
		
		// Check 2
		val lhs2 = (aPrime.multiply(n).add(BigInteger.ONE)).multiply(rPrime.mod(n))
		val rhs2 = beta.modPow(a, nSquared).multiply(pi.modInverse(nSquared)).multiply(gamma.modPow(e.negate(), nSquared)).mod(nSquared)
		
		if (rhs2 != lhs2)
			return false
		
		// Check 3
		val lhs3 = aPrime
		val rhs3 = BigInteger.ZERO
		
		if (rhs3 != lhs3)
			return false
		
		return true
	}
	fun checkEncryption(result: Pair<Pair<BigInteger, BigInteger>, Pair<BigInteger, BigInteger>>, n: BigInteger): Boolean {
		return checkEncryption(result.first, result.second, n)
	}
}