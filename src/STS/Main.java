package STS;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.ArrayList;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        User Alice = new User();
        User Bob = new User();
        Alice.RSAkeyPair = RSA.generate_key_pairs();
        Bob.RSAkeyPair = RSA.generate_key_pairs();
        CertificateAuthority.RSAkeyPair = RSA.generate_key_pairs();
        ArrayList<BigInteger> request = Alice.initiate_protocol();
        Object[] response = Bob.parse_request(request, "Bob");
        Object[] response_verify = Alice.verify_communication(response, "Alice");
        Bob.verify_communication_other_side(response_verify);
    }
}
