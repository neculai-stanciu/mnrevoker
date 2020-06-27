package ro.stit.service;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

import javax.inject.Singleton;

import ro.stit.dto.CertificateSummary;

@Singleton
public class SummaryMapperService {
  private Map<BigInteger, CertificateSummary> serialNumberToSummary;
  public Map<BigInteger, CertificateSummary> getSerialNumberToSummary() {
    return new HashMap<>(serialNumberToSummary);
  }

  public synchronized void  setSerialNumberToSummary(Map<BigInteger, CertificateSummary> serialNumberToSummary) {
    this.serialNumberToSummary = serialNumberToSummary;
  }

}
