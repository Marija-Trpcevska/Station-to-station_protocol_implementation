package STS;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;

public class CertificateAuthority {
    static KeyPair RSAkeyPair;

    public static class STSCertificate{
        String ID;
        BigInteger generator;
        BigInteger cyclic_group;
        PublicKey publicKey;
        byte[] signature;

        public STSCertificate(String id, BigInteger generator, BigInteger cyclic_group, PublicKey publicKey, byte[] signed_data) {
            this.ID = id;
            this.generator = generator;
            this.cyclic_group = cyclic_group;
            this.publicKey = publicKey;
            this.signature = signed_data;
        }
    }

    public static STSCertificate generateCertificate(String ID, BigInteger generator, BigInteger cyclic_group, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA512/256withRSA");
        signature.initSign(RSAkeyPair.getPrivate(),new SecureRandom());
        ByteBuffer byteBuffer = ByteBuffer.allocate(ID.getBytes(StandardCharsets.UTF_8).length+generator.toByteArray().length+cyclic_group.toByteArray().length+publicKey.getEncoded().length);
        byteBuffer.put(ID.getBytes(StandardCharsets.UTF_8));
        byteBuffer.put(generator.toByteArray());
        byteBuffer.put(cyclic_group.toByteArray());
        byteBuffer.put(publicKey.getEncoded());
        signature.update(byteBuffer);
        byte[] signed_data = signature.sign();
        return new STSCertificate(ID, generator, cyclic_group, publicKey, signed_data);
    }

    public static boolean verifyCertificate(STSCertificate stsCertificate) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA512/256withRSA");
        signature.initVerify(RSAkeyPair.getPublic());

        ByteBuffer byteBuffer_new = ByteBuffer.allocate(stsCertificate.ID.getBytes(StandardCharsets.UTF_8).length+stsCertificate.generator.toByteArray().length+stsCertificate.cyclic_group.toByteArray().length+stsCertificate.publicKey.getEncoded().length);
        byteBuffer_new.put(stsCertificate.ID.getBytes(StandardCharsets.UTF_8));
        byteBuffer_new.put(stsCertificate.generator.toByteArray());
        byteBuffer_new.put(stsCertificate.cyclic_group.toByteArray());
        byteBuffer_new.put(stsCertificate.publicKey.getEncoded());
        signature.update(byteBuffer_new);

        return signature.verify(stsCertificate.signature);
    }



}
