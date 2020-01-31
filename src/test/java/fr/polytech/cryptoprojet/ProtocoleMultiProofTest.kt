package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import org.junit.Test
import java.math.BigInteger
import kotlin.test.Asserter
import kotlin.test.assertEquals

class ProtocoleMultiProofTest: Asserter {
    val paillier= Paillier.randomCryptaception()
    
    @Test
    fun secureMultiplication() {
        val x=5
        val y=23
        val productxy=x*y
        val X= paillier.encrypt(BigInteger.valueOf(x.toLong()))
        val Y= paillier.encrypt(BigInteger.valueOf(y.toLong()))
        val protocol = ProtocoleMultiProof(paillier)
        val XY = protocol.secureMultiplication(X,Y)
        val xy = paillier.decryptToBigInteger(XY)
        
        println("x=$x, y=$y")
        println("$x * $y = ${x*y}")
        println("Decrypt(xy) = $xy")
        assertEquals(BigInteger.valueOf(productxy.toLong()),xy)
    }
    
    override fun fail(message: String?): Nothing {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
    
}