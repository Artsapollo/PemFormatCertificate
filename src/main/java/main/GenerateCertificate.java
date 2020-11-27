package main;

import org.bouncycastle.openssl.PEMWriter;
import sun.security.x509.*;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.Date;

public class GenerateCertificate {

    public static void main(String[] args) throws Exception {
        createAndSavePair("MyPub.cer.pem", "MyPrv.pem");
    }

    private static void createAndSavePair(String publicName, String privateName) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        VtsPair vtsPair = generateCertificate("CN=Me, L=City, C=Country", keyPair, 720, "SHA1withRSA");
        writePemFile(vtsPair, publicName, privateName);
    }

    /**
     * Create a self-signed X.509 Certificate
     *
     * @param dn        the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
     * @param pair      the KeyPair
     * @param days      how many days from now the Certificate is valid for
     * @param algorithm the signing algorithm, eg "SHA1withRSA"
     */
    static VtsPair generateCertificate(String dn, KeyPair pair, int days, String algorithm) throws Exception {
        VtsPair vtsPair = new VtsPair();

        PrivateKey privkey = pair.getPrivate();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);

        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);

        X509CertInfo info = new X509CertInfo();
        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));


        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);

        // Update the algorithm, and resign.
        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);

        vtsPair.setPublicCertificate(cert);
        vtsPair.setPrivateKey(privkey);
        return vtsPair;
    }

    //Save certificate and private key to file
    private static void writePemFile(VtsPair vtsPair, String publicName, String privateName) throws IOException {
        PEMWriter pemWriter = new PEMWriter(new OutputStreamWriter(new FileOutputStream(publicName)));
        pemWriter.writeObject(vtsPair.getPublicCertificate());
        pemWriter.flush();

        pemWriter = new PEMWriter(new OutputStreamWriter(new FileOutputStream(privateName)));
        pemWriter.writeObject(vtsPair.getPrivateKey());
        pemWriter.flush();
    }
}