package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import main.ExtendsPaillier.PaillierExtended
import java.math.BigInteger
import kotlin.test.assertEquals

fun main() {
	val paillier = PaillierExtended.randomCryptaception()
	val x = /*"Coucou 👋"*/3
	val y = /*"Bye 🧨"*/5
	val X = paillier.encrypt(x)
	val Y = paillier.encrypt(y)
	
	val alice = Alice(paillier)
	val bob = Bob(X, Y)
	
	println("mult1")
	val result = bob.mult1(alice.paillier)
	println(paillier.decryptToInt(result.first).toString() + " = $x + ${bob.u}")
	assert(paillier.decryptToBigInteger(result.first) == BigInteger.valueOf(x.toLong()).add(bob.u))
	println(paillier.decryptToInt(result.second).toString() + " = $y + ${bob.v}")
	assert(paillier.decryptToBigInteger(result.second) == BigInteger.valueOf(y.toLong()).add(bob.v))
	val encrypt = alice.multi2(result)
	println("mult2")
	println(paillier.decryptToInt(encrypt).toString() + " = ($x + ${bob.u}) * ($y + ${bob.v})")
	assert(paillier.decryptToBigInteger(encrypt) == (BigInteger.valueOf(x.toLong()).add(bob.u)).multiply(BigInteger.valueOf(y.toLong()).add(bob.v)))
	val xy = bob.multi3(alice.paillier, encrypt)
	println("mult3")
	val decryptedMult3 = paillier.decryptToInt(xy)
	println("decrypt of mult3:$decryptedMult3")
	
	assertEquals(decryptedMult3,x*y)
//	println("xy = $xy")
//	println(paillier.decryptToString(xy))
}

fun assert(value: Boolean) {
	if (!value)
		throw AssertionError("Assertion failed")
}
