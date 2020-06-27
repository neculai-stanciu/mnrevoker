package ro.stit.dto;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

/**
 * Represents the line in a CA's index file. The file is formatted with the
 * following fields separated by TAB characters.
 *
 * 1. Certificate status flag (V=valid, R=revoked, E=expired). 2. Certificate
 * expiration date in YYMMDDHHMMSSZ format. 3. Certificate revocation date in
 * YYMMDDHHMMSSZ[,reason] format. Empty if not revoked. 4. Certificate serial
 * number in hex. 5. Certificate filename or literal string ‘unknown’. 6.
 * Certificate distinguished name.
 *
 */
public class CertificateSummary {
  public static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyMMddHHmmssX");

  private final CertificateStatus status;
  private final LocalDateTime expirationTime;
  private final LocalDateTime revocationTime;
  private final RevocationReason revocationReason;
  private final BigInteger serialNumber;
  private final String fileName;
  private final X500Principal subjectDN;

  private final LocalDateTime thisUpDateTime;

  public CertificateStatus getStatus() {
    return status;
  }

  public LocalDateTime getExpirationTime() {
    return expirationTime;
  }

  public Date getExpirationTimeDate() {
    return expirationTime == null ? null : Date.from(expirationTime.toInstant(ZoneOffset.UTC));
  }

  public LocalDateTime getRevocationTime() {
    return revocationTime;
  }

  public Date getRevocationTimeDate() {
    return revocationTime == null ? null : Date.from(revocationTime.toInstant(ZoneOffset.UTC));
  }

  public RevocationReason getRevocationReason() {
    return revocationReason;
  }

  public BigInteger getSerialNumber() {
    return serialNumber;
  }

  public String getFileName() {
    return fileName;
  }

  public X500Principal getSubjectDN() {
    return subjectDN;
  }

  public LocalDateTime getThisUpDateTime() {
    return thisUpDateTime;
  }

  private CertificateSummary(Builder builder) {
    status = builder.status;
    expirationTime = builder.expirationTime;
    revocationTime = builder.revocationTime;
    revocationReason = builder.revocationReason;
    serialNumber = builder.serialNumber;
    fileName = builder.fileName;
    subjectDN = builder.subjectDN;
    thisUpDateTime = builder.thisUpdateTime == null ? LocalDateTime.now() : builder.thisUpdateTime;
  }

  public static Builder newBuilder() {
    return new Builder();
  }

  public static final class Builder {
    private CertificateStatus status = CertificateStatus.UNKNOWN;
    private LocalDateTime expirationTime = null;
    private LocalDateTime revocationTime = null;
    private RevocationReason revocationReason = null;
    private BigInteger serialNumber = null;
    private String fileName = null;
    private X500Principal subjectDN = null;

    private LocalDateTime thisUpdateTime = null;

    private Builder() {
    }

    public Builder withStatus(CertificateStatus val) {
      status = val;
      return this;
    }

    public Builder withExpirationTime(LocalDateTime val) {
      expirationTime = val;
      return this;
    }

    public Builder withRevocationTime(LocalDateTime val) {
      revocationTime = val;
      return this;
    }

    public Builder withRevocationReason(RevocationReason val) {
      revocationReason = val;
      return this;
    }

    public Builder withSerialNumber(BigInteger val) {
      serialNumber = val;
      return this;
    }

    public Builder withFileName(String val) {
      fileName = val;
      return this;
    }

    public Builder withSubjectDN(X500Principal val) {
      subjectDN = val;
      return this;
    }

    // @VisibleForTesting
    public Builder withThisUpdateTime(LocalDateTime val) {
      thisUpdateTime = val;
      return this;
    }

    public CertificateSummary build() {
      return new CertificateSummary(this);
    }
  }

  public static CertificateSummary parseLine(String indexLine) {
    List<String> fields = Arrays.asList(indexLine.split("\t"));

    // 0 = status
    CertificateStatus status = CertificateStatus.fromString(fields.get(0));
    // 1 = expiration time
    LocalDateTime expirationTime = LocalDateTime.parse(fields.get(1), DATE_TIME_FORMATTER);
    if (expirationTime.isBefore(LocalDateTime.now()) && status != CertificateStatus.REVOKED) {
      status = CertificateStatus.EXPIRED;
    }

    LocalDateTime revocationTime = null;
    RevocationReason revocationReason = null;
    if (!fields.get(2).isEmpty()) { // Will be empty if not revoked
      List<String> revocation = Arrays.asList(fields.get(2).split(","));
      revocationTime = LocalDateTime.parse(revocation.get(0), DATE_TIME_FORMATTER);
      if (revocation.size() > 1) { // Could be no reason given
        revocationReason = RevocationReason.fromName(revocation.get(1));
      }
    }

    // 3 = serial number in hex
    BigInteger serialNumber = new BigInteger(fields.get(3), 16);

    // 4 filename or "unknown"
    String fileName = null;
    if (!fields.get(4).equals("unknown")) {
      fileName = fields.get(4);
    }

    // 5 = DN of certificate
    String dnString = fields.get(5).trim();
    dnString = dnString.substring(dnString.indexOf("/") + 1); // strip first slash
    dnString = dnString.replaceAll("/", ", "); // replace remaining slashes with ", " separator
    X500Principal dn = new X500Principal(dnString);

    return CertificateSummary.newBuilder().withStatus(status).withExpirationTime(expirationTime)
        .withRevocationTime(revocationTime).withRevocationReason(revocationReason).withSerialNumber(serialNumber)
        .withFileName(fileName).withSubjectDN(dn).build();

  }

}
