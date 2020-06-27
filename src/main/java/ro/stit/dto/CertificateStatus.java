package ro.stit.dto;

public enum CertificateStatus {
  VALID, REVOKED, EXPIRED, UNKNOWN;

  public static CertificateStatus fromString(String status) {
    switch (status) {
      case "V":
        return VALID;
      case "R":
        return REVOKED;
      case "E":
        return EXPIRED;
      default:
        throw new IllegalArgumentException("Status provided is not valid: " + status);
    }
  }
}
