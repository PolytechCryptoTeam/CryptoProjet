package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import org.junit.Test
import java.math.BigInteger
import kotlin.test.Asserter
import kotlin.test.assertEquals

class ProtocoleMultiplicationTest: Asserter {
    val paillier= Paillier.randomCryptaception()
    val pk=paillier.publicKey
    val sk=paillier.secretKey
    
    @Test
    fun secureMultiplication() {
        val x=5
        val y=23
        val productxy=x*y
        val X= PaillierStatic.encrypt(BigInteger.valueOf(x.toLong()),pk)
        val Y= PaillierStatic.encrypt(BigInteger.valueOf(y.toLong()),pk)
        val protocol = ProtocoleMultiplication(paillier)
        val xy=protocol.secureMultiplication(X,Y)
        assertEquals(BigInteger.valueOf(productxy.toLong()),xy)
        
        
    }
    
    override fun fail(message: String?): Nothing {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
    
}