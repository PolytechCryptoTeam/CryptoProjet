import junit.framework.Assert.assertEquals
import main.ExtendsPaillier.PaillierExtended
import org.junit.Test

import java.math.BigInteger

internal class PaillierExtendedTest {
	lateinit var paillier: PaillierExtended

	fun setUp() {
		paillier= PaillierExtended.randomCryptaception(512)
	}

	@Test
	fun homomorphicAddition() {
		setUp()

		val x=BigInteger.valueOf(6)
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
//
//	@Test
//	fun homomorphicMultiplication() {
//	}
}