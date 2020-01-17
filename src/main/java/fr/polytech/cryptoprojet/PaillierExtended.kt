package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Cryptaception
import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger
import java.util.*

class PaillierStatic {
	companion object {
		
		fun encrypt(message: BigInteger, publicKey: BigInteger): BigInteger {
			val r = BigInteger(publicKey.bitLength(), Random()).mod(publicKey)
			// M = (1 + m * n) * r^n mod n²
			val M = (BigInteger.ONE.plus(message.multiply(publicKey))).multiply(r.modPow(publicKey, publicKey.pow(2)))
			return M
		}
		
		fun decryptToBigInteger(encryptedMessage: BigInteger, publicKey: BigInteger, secretKey: BigInteger): BigInteger {
			val r = encryptedMessage.modPow(secretKey, publicKey)
			// m = ((M * r^(-n) mod n²) - 1)/n
			val m = (encryptedMessage.multiply(r.modPow(publicKey, publicKey.pow(2)).modInverse(publicKey.pow(2))))
				.mod(publicKey.pow(2)).subtract(BigInteger.ONE).divide(publicKey)
			return m
		}
	}
	
}