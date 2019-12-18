package fr.polytech.cryptoprojet

import fr.polytech.berger.cryptaception.Paillier
import java.math.BigInteger

class PaillierPlus(
    publicKey: BigInteger,
    secretKey: BigInteger
): Paillier(publicKey, secretKey) {

    fun decryptPlus(encryptedBigInteger: BigInteger): Pair<BigInteger, BigInteger> {
        // r = (M mod n)^rho
        val r = encryptedBigInteger.modPow(secretKey, publicKey)
        // m = ((M * r^(-n) mod n²) - 1)/n
        val m = (encryptedBigInteger.multiply(r.modPow(publicKey, publicKey.pow(2)).modInverse(publicKey.pow(2))))
            .mod(publicKey.pow(2)).subtract(BigInteger.ONE).divide(publicKey)
        return Pair(m, r)
    }
}