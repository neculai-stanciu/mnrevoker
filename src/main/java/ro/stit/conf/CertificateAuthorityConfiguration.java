package ro.stit.conf;

import java.util.Collections;
import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.Min;
import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.micronaut.context.annotation.ConfigurationProperties;
import ro.stit.dto.CRLNameFilePair;

@ConfigurationProperties("certificate-authority")
public class CertificateAuthorityConfiguration {

  /**
   * The file containing the CA's index.
   */
  @NotEmpty
  @JsonProperty
  private String caIndexFile;

  /**
   * How long to refresh the certificate status from the CA's index file in
   * seconds. Defaults to 300 (5 minutes).
   */
  @Min(0)
  @JsonProperty
  private int refreshSeconds = 300;

  @Valid
  @NotEmpty
  @JsonProperty
  private List<CRLNameFilePair> crlFiles = Collections.emptyList();

  public String getCaIndexFile() {
    return caIndexFile;
  }

  public void setCaIndexFile(String caIndexFile) {
    this.caIndexFile = caIndexFile;
  }

  public int getRefreshSeconds() {
    return refreshSeconds;
  }

  public void setRefreshSeconds(int refreshSeconds) {
    this.refreshSeconds = refreshSeconds;
  }

  public List<CRLNameFilePair> getCrlFiles() {
    return crlFiles;
  }

  public void setCrlFiles(List<CRLNameFilePair> crlFiles) {
    this.crlFiles = crlFiles;
  }

}
