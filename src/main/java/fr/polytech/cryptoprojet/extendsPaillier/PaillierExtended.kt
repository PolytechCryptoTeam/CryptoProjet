package main.ExtendsPaillier

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger

class PaillierExtended(_publicKey: BigInteger, _secretKey: BigInteger) : Paillier(_publicKey, _secretKey) {
	
	//region STATIC CONTEXT
	
	companion object {
		fun randomCryptaception(keySizeBits: Int = DEFAULT_KEY_SIZE_BITS): PaillierExtended {
			val paillier = PaillierExtended(BigInteger.ZERO, BigInteger.ZERO)
			val bunch = paillier.keyGen(keySizeBits)
			
			return PaillierExtended(bunch.first, bunch.second)
		}
	}
	
	//endregion
	
	
	private var nSquare=_publicKey.multiply(_publicKey)
	
	fun homomorphicAddition(encryptedNumberFirst: BigInteger, encryptedNumberSecond: BigInteger): BigInteger{
		return encryptedNumberFirst.multiply(encryptedNumberSecond).mod(nSquare)
	}
	
	fun homomorphicMultiplication(encryptedNumberFirst: BigInteger, plainTextNumberSecond: BigInteger): BigInteger{
		return encryptedNumberFirst.modPow(plainTextNumberSecond,nSquare)
	}
	
	fun homomorphicMultiplication(encryptedNumberFirst: BigInteger, plainTextNumberSecond: Long): BigInteger{
		return homomorphicMultiplication(encryptedNumberFirst,BigInteger.valueOf(plainTextNumberSecond))
	}
}