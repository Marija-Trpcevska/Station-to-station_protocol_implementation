package STS;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.ArrayList;

public class User {
    KeyPair RSAkeyPair;
    BigInteger DHKey;
    int exponent;
    BigInteger generator;
    BigInteger cyclic_group_p;
    BigInteger g_pow_a;

    public ArrayList<BigInteger> initiate_protocol(){
        BigInteger generator = new BigInteger("5");
        this.generator = generator;
        System.out.println("GENERATOR: "+generator);

        BigInteger cyclic_group_p = new BigInteger("7");
        this.cyclic_group_p = cyclic_group_p;
        System.out.println("CYCLIC_GROUP: "+cyclic_group_p);

        this.exponent = (int)(Math.random()*(100-10)+10);
        System.out.println("ALICE EXPONENT A: "+this.exponent);

        BigInteger g_pow_a = generator.pow(this.exponent);
        System.out.println("ALICE G^A: "+g_pow_a);

        ArrayList<BigInteger> request = new ArrayList<>();
        request.add(generator);
        request.add(cyclic_group_p);
        request.add(g_pow_a);
        return request;
    }

    public Object[] parse_request(ArrayList<BigInteger> request, String ID) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        BigInteger generator = request.get(0);
        this.generator = generator;
        BigInteger cyclic_group_p = request.get(1);
        this.cyclic_group_p = cyclic_group_p;
        BigInteger g_pow_a = request.get(2);
        this.g_pow_a = g_pow_a;

        this.exponent =  (int)(Math.random()*(100-10)+10);
        System.out.println("BOB EXPONENT B: "+exponent);
        BigInteger g_pow_b = generator.pow(this.exponent);
        System.out.println("BOB G^B: "+g_pow_b);
        BigInteger K = g_pow_a.pow(this.exponent);
        System.out.println("SHARED SECRET KEY: "+K);
        this.DHKey = K;

        Signature signature = Signature.getInstance("SHA512/256withRSA");
        signature.initSign(this.RSAkeyPair.getPrivate(),new SecureRandom());
        ByteBuffer byteBuffer = ByteBuffer.allocate(g_pow_b.toByteArray().length+g_pow_a.toByteArray().length);
        byteBuffer.put(g_pow_b.toByteArray());
        byteBuffer.put(g_pow_a.toByteArray());
        signature.update(byteBuffer);
        byte[] signed_data = signature.sign();
        System.out.println("BOB SIGNED PAYLOAD: "+format_array(signed_data));

        byte[] encrypted_data = AES.encrypt(signed_data, K.toString());
        assert encrypted_data != null;
        System.out.println("BOB ENCRYPTED PAYLOAD: "+format_array(encrypted_data));

        CertificateAuthority.STSCertificate stsCertificate = CertificateAuthority.generateCertificate(ID,generator, cyclic_group_p, this.RSAkeyPair.getPublic());
        System.out.println("CA SIGNATURE OVER BOB'S INFORMATION (ID, G, P, PUBLIC_KEY): "+ format_array(stsCertificate.signature));

        Object[] response = new Object[3];
        response[0] = g_pow_b;
        response[1] = stsCertificate;
        response[2] = encrypted_data;
        return response;
    }

    public Object[] verify_communication(Object[] response, String ID) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

        CertificateAuthority.STSCertificate stsCertificate_received = (CertificateAuthority.STSCertificate)response[1];
        if(CertificateAuthority.verifyCertificate(stsCertificate_received)){
            System.out.println("VERIFIED CERTIFICATE SUCCESSFULLY FOR "+stsCertificate_received.ID);
            BigInteger g_pow_b_received = (BigInteger)response[0];
            BigInteger K = g_pow_b_received.pow(this.exponent);
            this.DHKey = K;
            byte[] decrypted_data = AES.decrypt((byte[])response[2], K.toString());
            BigInteger g_pow_a = this.generator.pow(this.exponent);
            Signature signature = Signature.getInstance("SHA512/256withRSA");
            signature.initVerify(stsCertificate_received.publicKey);
            ByteBuffer byteBuffer = ByteBuffer.allocate(g_pow_b_received.toByteArray().length+g_pow_a.toByteArray().length);
            byteBuffer.put(g_pow_b_received.toByteArray());
            byteBuffer.put(g_pow_a.toByteArray());
            signature.update(byteBuffer);
            if(signature.verify(decrypted_data)){
                System.out.println("VERIFIED SIGNED PAYLOAD SUCCESSFULLY FROM "+stsCertificate_received.ID);
                Signature signature_self = Signature.getInstance("SHA512/256withRSA");
                signature_self.initSign(this.RSAkeyPair.getPrivate(),new SecureRandom());
                ByteBuffer byteBuffer_self = ByteBuffer.allocate(g_pow_b_received.toByteArray().length+g_pow_a.toByteArray().length);
                byteBuffer_self.put(g_pow_a.toByteArray());
                byteBuffer_self.put(g_pow_b_received.toByteArray());
                signature_self.update(byteBuffer_self);
                byte[] signed_data = signature_self.sign();
                System.out.println("ALICE SIGNED PAYLOAD: "+format_array(signed_data));

                byte[] encrypted_data = AES.encrypt(signed_data,K.toString());
                assert encrypted_data != null;
                System.out.println("ALICE ENCRYPTED PAYLOAD: "+format_array(encrypted_data));

                CertificateAuthority.STSCertificate stsCertificate = CertificateAuthority.generateCertificate(ID,this.generator, this.cyclic_group_p, this.RSAkeyPair.getPublic());
                System.out.println("CA SIGNATURE OVER ALICES'S INFORMATION (ID, G, P, PUBLIC_KEY): "+ format_array(stsCertificate.signature));

                Object[] response_self = new Object[2];
                response_self[0] = stsCertificate;
                response_self[1] = encrypted_data;
                return response_self;
            }
            return null;
        }
        return null;
    }

    public void verify_communication_other_side(Object[] response) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        CertificateAuthority.STSCertificate stsCertificate_received = (CertificateAuthority.STSCertificate)response[0];
        if(CertificateAuthority.verifyCertificate(stsCertificate_received)){
            System.out.println("VERIFIED CERTIFICATE SUCCESSFULLY FOR "+stsCertificate_received.ID);
            byte[] decrypted_data = AES.decrypt((byte[])response[1],this.DHKey.toString());
            BigInteger g_pow_b = this.generator.pow(this.exponent);
            Signature signature = Signature.getInstance("SHA512/256withRSA");
            signature.initVerify(stsCertificate_received.publicKey);
            ByteBuffer byteBuffer_self = ByteBuffer.allocate(this.g_pow_a.toByteArray().length+g_pow_b.toByteArray().length);
            byteBuffer_self.put(this.g_pow_a.toByteArray());
            byteBuffer_self.put(g_pow_b.toByteArray());
            signature.update(byteBuffer_self);
            if(signature.verify(decrypted_data)){
                System.out.println("VERIFIED SIGNED PAYLOAD SUCCESSFULLY FROM "+stsCertificate_received.ID);
                System.out.println("---------------------------------------------------------------------");
                System.out.println("SUCCESSFULLY CONCLUDED STS PROTOCOL");
            }

        }

    }

    public String format_array(byte[] array){
        StringBuilder str = new StringBuilder(" ");
        for(byte b : array){
            str.append(String.format("%x", b)).append(" ");
        }
        return String.valueOf(str);
    }

}
