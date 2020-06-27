package ro.stit.service;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.stream.Stream;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ro.stit.conf.OCSPResponderConf;

@Singleton
public class OCSPResponderService {
  public static final Logger LOG = LoggerFactory.getLogger(OCSPResponderService.class);

  OCSPResponderConf ocspResponderConf;

  @Inject
  public OCSPResponderService(OCSPResponderConf ocspResponderConf) {
    this.ocspResponderConf = ocspResponderConf;

  }

  private Optional<KeyStore> loadOcspKeyStore() {
    try {
      var resourceUrl = this.getClass().getClassLoader().getResource(ocspResponderConf.getKeyStorePath()).toURI();
      var keyStorePath = Path.of(resourceUrl);
      var ocspKeyStore = KeyStore.getInstance(ocspResponderConf.getKeyStoreType());
      LOG.info("ocspResponderConf.getKeyStorePath() = {} ", keyStorePath);

      ocspKeyStore.load(Files.newInputStream(keyStorePath), ocspResponderConf.getKeyStorePassphrase().toCharArray());
      return Optional.of(ocspKeyStore);

    } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | URISyntaxException e) {
      LOG.error("Could not instantiate keystore", e);
      return Optional.empty();
    }
  }

  public X509Certificate[] extractOCSPX509CertificateChain() {
    var ocspKeyStoreAlias = ocspResponderConf.getKeyStoreAlias();
    var ocspKeyStore = loadOcspKeyStore().orElseThrow();
    Optional<Certificate[]> ocspCertificateChain;
    try {
      ocspCertificateChain = Optional.of(ocspKeyStore.getCertificateChain(ocspKeyStoreAlias));
    } catch (KeyStoreException e) {
      LOG.error("Unable to read keystore certificate", e);

      ocspCertificateChain = Optional.empty();
    }
    var ocspX509CertificateChain = Stream.of(ocspCertificateChain).flatMap(certArr -> Stream.of(certArr.get()))
        .map(cert -> (X509Certificate) cert).toArray(X509Certificate[]::new);
    return ocspX509CertificateChain;
  }

  public X509CertificateHolder[] asBouncyCastleFormat(X509Certificate[] signingCertificateChain) {
    return Stream.of(signingCertificateChain).map(cert -> {
      try {
        return new JcaX509CertificateHolder(cert);
      } catch (CertificateEncodingException e) {
        throw new RuntimeException("Issue on conversion");
      }
    }).toArray(X509CertificateHolder[]::new);
  }

  public Optional<X509CertificateHolder> getIssuingCertificate() {
    var certChain = extractOCSPX509CertificateChain();
    var bouncyCastleCertificateChain = asBouncyCastleFormat(certChain);
    if (bouncyCastleCertificateChain.length >= 2) {
      return Optional.of(bouncyCastleCertificateChain[1]);
    }
    return Optional.empty();
  }

  public Optional<PrivateKey> extractOCSPSigningKey() {
    var ocspKeyStore = loadOcspKeyStore().orElseThrow();
    var ocspKeyStoreAlias = ocspResponderConf.getKeyStoreAlias();
    try {
      var privateKey = (PrivateKey) ocspKeyStore.getKey(ocspKeyStoreAlias,
          ocspResponderConf.getKeyStorePassphrase().toCharArray());
      return Optional.of(privateKey);
    } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
      LOG.error("Cannot extract private key:", e);
      return Optional.empty();
    }
  }

  public SubjectPublicKeyInfo extractPublicKeyInfo() {
    return SubjectPublicKeyInfo.getInstance(extractOCSPX509CertificateChain()[0].getPublicKey().getEncoded());
  }

  // todo: move to bean
  public Optional<DigestCalculatorProvider> createDigestCalculator() {
    try {
      var calculator = new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
      return Optional.of(calculator);

    } catch (OperatorCreationException e) {
      LOG.error("Unable to create DigestCalculatorProvider", e);
      return Optional.empty();
    }
  }

  public Optional<RespID> extractRespId() {
    var digestCalc = createDigestCalculator();
    var publicKeyInfo = extractPublicKeyInfo();
    if (digestCalc.isEmpty()) {
      LOG.debug("No digest calc");
      return Optional.empty();
    }
    try {
      return Optional.of(
          new RespID(publicKeyInfo, digestCalc.get().get(new DefaultDigestAlgorithmIdentifierFinder().find("SHA-1"))));
    } catch (OperatorCreationException | OCSPException e) {
      LOG.error("Unable to create resp id", e);
      return Optional.empty();
    }
  }

  public Optional<ContentSigner> createSigner() {
    var signingKey = extractOCSPSigningKey();
    if (signingKey.isEmpty()) {
      return Optional.empty();
    }
    try {
      return Optional
          .of(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(extractOCSPSigningKey().get()));
    } catch (OperatorCreationException e) {
      LOG.error("Cannot create signer", e);
      return Optional.empty();
    }
  }

}
