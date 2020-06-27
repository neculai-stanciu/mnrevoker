package ro.stit.conf;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import io.micronaut.context.annotation.ConfigurationProperties;

@ConfigurationProperties("ocsp-responder")
public class OCSPResponderConf {

  @NotEmpty
  private String keyStorePath;

//   @OneOf({
//     "JKS",          /** {@link sun.security.provider.Sun}      **/
//     "JCEKS",        /** {@link sun.security.ssl.SunJSSE}       **/
//     "PCKS12",       /** {@link com.sun.crypto.provider.SunJCE} **/
//     "Windows-MY",   /** {@link sun.security.mscapi.SunMSCAPI}  **/
//     "Windows-ROOT", /** {@link sun.security.mscapi.SunMSCAPI}  **/
//     "KeychainStore" /** {@link apple.security.AppleProvider}   **/
// })
  @NotEmpty
  private String keyStoreType = "JKS";

  @NotNull
  private String keyStorePassphrase = "";

      /**
     * The alias within the KeyStore to find the signing keys
     */
    @NotEmpty
    private String keyStoreAlias;

    /**
     * Whether to reject unknown certificates with "revoked" or return the "unknown" status.
     */
    private boolean rejectUnknown = false;

    public String getKeyStorePath() {
      return keyStorePath;
    }

    public void setKeyStorePath(String keyStorePath) {
      this.keyStorePath = keyStorePath;
    }

    public String getKeyStoreType() {
      return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
      this.keyStoreType = keyStoreType;
    }

    public String getKeyStorePassphrase() {
      return keyStorePassphrase;
    }

    public void setKeyStorePassphrase(String keyStorePassphrase) {
      this.keyStorePassphrase = keyStorePassphrase;
    }

    public String getKeyStoreAlias() {
      return keyStoreAlias;
    }

    public void setKeyStoreAlias(String keyStoreAlias) {
      this.keyStoreAlias = keyStoreAlias;
    }

    public boolean isRejectUnknown() {
      return rejectUnknown;
    }

    public void setRejectUnknown(boolean rejectUnknown) {
      this.rejectUnknown = rejectUnknown;
    }
}
