package main;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

@Data
@NoArgsConstructor
class VtsPair {
    private X509Certificate publicCertificate;
    private PrivateKey privateKey;
}