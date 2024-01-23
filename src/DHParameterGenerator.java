import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

public class DHParameterGenerator {

    public static void main(String[] args) {
        try {
            // Initialize KeyPairGenerator for Diffie-Hellman
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DH");

            // Generate the KeyPair
            keyPairGen.initialize(512);
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Extracting DHParameterSpec from generated keys
            DHPublicKey dhPublicKey = (DHPublicKey) keyPair.getPublic();
            DHParameterSpec dhSpec = dhPublicKey.getParams();

            // Randomly generate a secret key to be used to a public key
            SecureRandom secureRandom = new SecureRandom();
            BigInteger secretKey = new BigInteger(dhSpec.getP().bitLength(), secureRandom);
            secretKey = secretKey.mod(dhSpec.getP().subtract(BigInteger.ONE)).add(BigInteger.TWO);
            System.out.println("Secret Key: " + secretKey);
            BigInteger publicKey = dhSpec.getG().modPow(secretKey, dhSpec.getP());
            System.out.println("Public Key: " + publicKey);

            // Getting the values of p and g
            System.out.println("P (Prime Number): " + dhSpec.getP());
            System.out.println("G (Generator): " + dhSpec.getG());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
