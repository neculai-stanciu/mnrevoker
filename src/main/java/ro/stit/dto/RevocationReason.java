package ro.stit.dto;

import java.util.Map;

public enum RevocationReason {
  /**
   * Code = 0, Name = unspecified
   *
   * <p>
   * Can be used to revoke certificates for reasons other than the specific codes.
   * </p>
   */
  UNSPECIFIED(0, "unspecified"),
  /**
   * Code = 1, Name = keyCompromise
   *
   * <p>
   * Used in revoking an end-entity certificate. It indicates that it is known or
   * suspected that the subject's private key, or other aspects of the subject
   * validated in the certificate, have been compromised.
   * </p>
   */
  KEY_COMPROMISE(1, "keyCompromise"),
  /**
   * Code = 2, Name = CACompromise
   * <p>
   * Used in revoking a CA-certificate. It indicates that it is known or suspected
   * that the subject's private key, or other aspects of the subject validated in
   * the certificate, have been compromised.
   * </p>
   */
  CA_COMPROMISE(2, "CACompromise"),

  /**
   * Code = 3, Name = affiliationChanged
   * <p>
   * Indicates that the subject's name or other information in the certificate has
   * been modified but there is no cause to suspect that the private key has been
   * compromised.
   * </p>
   */
  AFFILIATION_CHANGED(3, "affiliationChanged"),

  /**
   * Code = 4, Name = superseded
   * <p>
   * Indicates that the certificate has been superseded but there is no cause to
   * suspect that the private key has been compromised.
   * </p>
   */
  SUPERSEDED(4, "superseded"),

  /**
   * Code = 5, Name = cessationOfOperation
   * <p>
   * Indicates that the certificate is no longer needed for the purpose for which
   * it was issued but there is no cause to suspect that the private key has been
   * compromised.
   * </p>
   */
  CESSATION_OF_OPERATION(5, "cessationOfOperation"),

  /**
   * Code = 6, Name = certificateHold
   * <p>
   * Indicates that the certificate is temporarily revoked but there is no cause
   * to suspect that the private kye has been compromised; the certificate can
   * later be revoked with another reason code, or unrevoked and returned to use.
   */
  CERTIFICATE_HOLD(6, "certificateHold"),

  /**
   * Code = 7, Name = unused
   * <p>
   * This certificate is obsolete and unused.
   * </p>
   */
  UNUSED(7, "unused"),

  /**
   * Code = 8, Name = removeFromCRL
   * <p>
   * Indicates that the certificate has been unrevoked. NOTE: This is specific to
   * the CertificateHold reason and is only used in DeltaCRLs.
   * </p>
   */
  REMOVE_FROM_CRL(8, "removeFromCRL"),

  /**
   * Code = 9, Name = privilegeWithdrawn
   * <p>
   * Indicates that a certificate (public-key or attribute certificate) was
   * revoked because a privilege contained within that certificate has been
   * withdrawn. Unused in OpenSSL.
   * </p>
   */
  PRIVILEGE_WITHDRAWN(9, "privilegeWithdrawn"),
  /**
   * Code = 10, Name = AACompromise
   * <p>
   * Indicates that it is known or suspected that aspects of the AA validated in
   * the attribute certificate, have been compromised. It applies to authority
   * attribute (AA) certificates only. Unused in OpenSSL.
   * </p>
   */
  AA_COMPROMISE(10, "AACompromise");

  private static final int NUM_CODES = 11;

  private int code;
  private String name;

  private RevocationReason(int code, String name) {
    this.code = code;
    this.name = name;
  }

  public int getCode() {
    return code;
  }

  public String getName() {
    return name;
  }

  public static RevocationReason fromCode(int code) {
    if (code > NUM_CODES - 1 || code < 0 || code == UNUSED.code) {
      throw new IllegalArgumentException("CRL Reason code not recognized: " + code);
    }
    return RevocationReason.values()[code];
  }

    // Map for quick lookups by name.
    private static Map<String, RevocationReason> nameToReason = Map.of(UNSPECIFIED.getName(), UNSPECIFIED,
    KEY_COMPROMISE.getName(), KEY_COMPROMISE, CA_COMPROMISE.getName(), CA_COMPROMISE, AFFILIATION_CHANGED.getName(),
    AFFILIATION_CHANGED, SUPERSEDED.getName(), SUPERSEDED, CESSATION_OF_OPERATION.getName(), CESSATION_OF_OPERATION,
    CERTIFICATE_HOLD.getName(), CERTIFICATE_HOLD,
    // .put(UNUSED .getName(), UNUSED ) Skip Unused / Obsolete
    REMOVE_FROM_CRL.getName(), REMOVE_FROM_CRL, PRIVILEGE_WITHDRAWN.getName(), PRIVILEGE_WITHDRAWN,
    AA_COMPROMISE.getName(), AA_COMPROMISE);

  public static RevocationReason fromName(String name) {
    return nameToReason.get(name);
  }
}
