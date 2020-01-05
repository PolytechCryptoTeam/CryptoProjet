package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger
import kotlin.test.assertEquals

fun main() {
	val paillier = Paillier.randomCryptaception()
	val x = /*"Coucou 👋"*/3
	val y = /*"Bye 🧨"*/5
	val X = paillier.encrypt(x)
	val Y = paillier.encrypt(y)
	var big_x: BigInteger? = null
	var big_y: BigInteger? = null
	try {
		big_x = BigInteger.valueOf(x.toLong())
		big_y = BigInteger.valueOf(y.toLong())
	} catch (e: NumberFormatException) { }
	
	val alice = Alice(paillier)
	val bob = Bob(X, Y)
	
	val pair = bob.mult1(alice.paillier)
	if (big_x != null && big_y != null) {
		println("mult1")
		println(paillier.decryptToInt(pair.first).toString() + " ≟ $x + ${bob.u}")
		// Decrypt(E(u) * X) = u + x
		assert(paillier.decryptToBigInteger(pair.first) == big_x.add(bob.u))
		println(paillier.decryptToInt(pair.second).toString() + " ≟ $y + ${bob.v}")
		// Decrypt(E(v) * Y) = v + y
		assert(paillier.decryptToBigInteger(pair.second) == big_y.add(bob.v))
	}
	
	val product = alice.mult2(pair)
	if (big_x != null && big_y != null) {
		println("\nmult2")
		println(
			paillier.decryptToInt(product).toString() + " ≟ ($x + ${bob.u}) * ($y + ${bob.v}) mod ${paillier.publicKey.toString().take(5)}... (${paillier.publicKey.toString().length} digits)"
		)
		// Decrypt((E(u) * X)^(E(v) * Y)) = (u + x) * (v + y)
		assert(paillier.decryptToBigInteger(product) == (big_x.add(bob.u)).multiply(big_y.add(bob.v)))
	}
	
	val xy = bob.mult3(alice.paillier, product)
	if (big_x != null && big_y != null) {
		println("\nmult3")
		println("(${bob.u} + $x) * (${bob.v} + $y) - ${bob.v} * $x - ${bob.u} * $y - ${bob.u} * ${bob.v} = " + bob.u.add(big_x).multiply(bob.v.add(big_y)).subtract(bob.v.multiply(big_x)).subtract(bob.u.multiply(big_y)).subtract(bob.u.multiply(bob.v)) + " ≟ ${paillier.decryptToInt(xy)}")
		assertEquals(bob.u.add(big_x).multiply(bob.v.add(big_y)).subtract(bob.v.multiply(big_x)).subtract(bob.u.multiply(big_y)).subtract(bob.u.multiply(bob.v)), paillier.decryptToBigInteger(xy))
		println("$x * $y ≟ " + paillier.decryptToInt(xy).toString())
		assertEquals(big_x.multiply(big_y), paillier.decryptToBigInteger(xy))
	}
	println("To string:\n" + paillier.decryptToString(xy))
}

fun assert(value: Boolean) {
	if (!value)
		throw AssertionError("Assertion failed")
}
