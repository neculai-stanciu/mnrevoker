package ro.stit.dto;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;

public class OCSPCertificateStatusWrapper {
  private org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus;
  private LocalDateTime thisUpdate;
  private LocalDateTime nextUpdate;

  public OCSPCertificateStatusWrapper(org.bouncycastle.cert.ocsp.CertificateStatus certificateStatus,
      LocalDateTime thisUpdate, LocalDateTime nextUpdate) {
    this.certificateStatus = certificateStatus;
    this.thisUpdate = thisUpdate;
    this.nextUpdate = nextUpdate;
  }

  public org.bouncycastle.cert.ocsp.CertificateStatus getCertificateStatus() {
    return certificateStatus;
  }

  public LocalDateTime getNextUpdate() {
    return nextUpdate;
  }

  public Date getNextUpdateDate() {
    return nextUpdate == null ? null : Date.from(this.nextUpdate.toInstant(ZoneOffset.UTC));
  }

  public LocalDateTime getThisUpdate() {
    return thisUpdate;
  }

  public Date getThisUpdateDate() {
    return thisUpdate == null ? null : Date.from(thisUpdate.toInstant(ZoneOffset.UTC));
  }

}
