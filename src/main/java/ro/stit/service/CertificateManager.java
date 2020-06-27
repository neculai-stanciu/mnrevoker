package ro.stit.service;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ro.stit.conf.CertificateAuthorityConfiguration;
import ro.stit.dto.CertificateStatus;
import ro.stit.dto.CertificateSummary;

@Singleton
public class CertificateManager {
  private static final Logger LOG = LoggerFactory.getLogger(CertificateManager.class);

  private CertificateAuthorityConfiguration caConfiguration;
  private Map<String, X509CRL> crlMap = new HashMap<>();
  private SummaryMapperService summaryMapperService;

  @Inject
  public CertificateManager(CertificateAuthorityConfiguration caConf, SummaryMapperService summaryMapperService) {
    this.caConfiguration = caConf;
    this.summaryMapperService = summaryMapperService;
  }

  public CertificateSummary getSummary(BigInteger serialNumber) {
    LOG.debug("Requested summary for certificate with serial {}", serialNumber);

    CertificateSummary summary = summaryMapperService.
            getSerialNumberToSummary()
            .get(serialNumber);

    if (summary != null) {
      return summary;
    } else {
      return CertificateSummary
          .newBuilder()
          .withStatus(CertificateStatus.UNKNOWN)
          .withSerialNumber(serialNumber)
          .build();
    }
  }

  public X509CRL getCRL(String name) {
    return crlMap.get(name);
  }

  public int getRefreshSeconds() {
    return caConfiguration.getRefreshSeconds();
  }
}
