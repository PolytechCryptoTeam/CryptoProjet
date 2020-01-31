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
	
	fun Multi2(n: BigInteger, random: Random = Random()): BigInteger {
		// e ∈ ℤ/nℤ
		e = BigInteger.probablePrime(Cryptaception.DEFAULT_KEY_SIZE_BITS, random).mod(n)
		return e
	}
	
	fun Multi4(ar: Pair<BigInteger, BigInteger>, arPrime: Pair<BigInteger, BigInteger>, n: BigInteger): Boolean {
		val a = ar.first
		val r = ar.second
		val aPrime = arPrime.first
		val rPrime = arPrime.second
		val nSquared = n.pow(2)
		
		// Check 1
		// (1 + a * n) * rⁿ mod n²
		val lhs1 = (BigInteger.ONE.add(a.multiply(n))).multiply(r.modPow(n, nSquared))
		// [α]ᵉ * [δ] mod n²
		val rhs1 = (alpha.modPow(e, nSquared)).multiply(delta).mod(nSquared)
		
		if (rhs1 != lhs1) {
			println("Bob.Multi4> Check 1 failed:\n$lhs1 != $rhs1")
			return false
		}
		
		// Check 2
		// (1 + a' * n) * r'ⁿ mod n²
		val lhs2 = (BigInteger.ONE.add(aPrime.multiply(n))).multiply(rPrime.modPow(n, nSquared))
		// [β]ᵃ * [π]⁻¹ * [γ]⁻ᵉ mod n²
		val rhs2 = (beta.modPow(a, nSquared)).multiply(pi.modInverse(nSquared)).multiply((gamma.modPow(e, nSquared)).modInverse(nSquared)).mod(nSquared)
		
		if (rhs2 != lhs2) {
			println("Bob.Multi4> Check 2 failed:\n$lhs2 != $rhs2")
			return false
		}
		
		// Check 3
		// a'
		val lhs3 = aPrime
		// 0
		val rhs3 = BigInteger.ZERO
		
		if (rhs3 != lhs3) {
			println("Bob.Multi4> Check 3 failed:\n$lhs3 != $rhs3")
			return false
		}
		
		return true
	}
	fun Multi4(result: Pair<Pair<BigInteger, BigInteger>, Pair<BigInteger, BigInteger>>, n: BigInteger): Boolean {
		return Multi4(result.first, result.second, n)
	}
}