package fr.polytech.cryptoprojet.extendsPaillier

import main.ExtendsPaillier.PaillierExtended

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.math.BigInteger

internal class PaillierExtendedTest {
	
	lateinit var paillier: PaillierExtended
	
	fun setUp() {
		paillier= PaillierExtended.randomCryptaception(512)
	}
	
	@Test
	fun homomorphicAddition() {
		setUp()
		
		val x= BigInteger.valueOf(6)
		val y=BigInteger.valueOf(4)
		val somme=x+y
		
		println("x="+x)
		println("y="+y)
		println("somme="+somme)
		
		val xEnc=paillier.encrypt(x)
		val yEnc=paillier.encrypt(y)
		val sommeEnc=paillier.homomorphicAddition(xEnc,yEnc)
		val sommeDec=paillier.decryptToInt(sommeEnc)
		
		println("somme decryptée="+sommeDec)
		assertEquals(somme,sommeDec)
		
	}
}