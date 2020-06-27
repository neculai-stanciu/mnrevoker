package ro.stit.service;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.scheduling.annotation.Scheduled;
import ro.stit.conf.CertificateAuthorityConfiguration;
import ro.stit.dto.CRLNameFilePair;
import ro.stit.dto.CertificateSummary;

@Singleton
public class CertificateDataUpdater {
  public static final Logger LOG = LoggerFactory.getLogger(CertificateDataUpdater.class);

  private final CertificateFactory certificateFactory;
  private CertificateAuthorityConfiguration caConf;

  private SummaryMapperService summaryMapperService;

  @Inject
  public CertificateDataUpdater(CertificateAuthorityConfiguration caConf, SummaryMapperService summaryMapperService)
      throws Exception {
    this.caConf = caConf;
    this.summaryMapperService = summaryMapperService;
    this.certificateFactory = CertificateFactory.getInstance("X.509");
  }

  @Scheduled(fixedRate = "30s")
  protected void run() throws Exception {
    try {
      parseIndexFile();
    } catch (Exception e) {
      LOG.error("Exception while reading index!", e);
      throw e;
    }

    try {
      refreshCRLs();
    } catch (Exception e) {
      LOG.error("Exception while reading CRLs!", e);
      throw e;
    }
  }

  public void parseIndexFile() throws IOException, URISyntaxException {
    LOG.debug("Reading index file at " + caConf.getCaIndexFile());
    var resourceUrl = this.getClass().getClassLoader().getResource(caConf.getCaIndexFile()).toURI();
    var caIndexPath = Path.of(resourceUrl);

    var newData = Files.readAllLines(caIndexPath).stream().map(CertificateSummary::parseLine)
        .collect(Collectors.toMap(CertificateSummary::getSerialNumber, Function.identity()));
    summaryMapperService.setSerialNumberToSummary(newData);
    LOG.info("Successfully read index file at: " + caIndexPath + ". Next iteration in 30 seconds");
  }

  public void refreshCRLs() {
    caConf.getCrlFiles().stream().collect(Collectors.toMap(CRLNameFilePair::getName, this::makeCRL));
  }

  private X509CRL makeCRL(CRLNameFilePair pair) {
    try (InputStream crlStream = this.getClass().getClassLoader().getResourceAsStream(pair.getFilePath())) {
      return (X509CRL) certificateFactory.generateCRL(crlStream);
    } catch (Exception e) {
      throw new IllegalStateException("Could not parse CRL: " + pair.getName(), e);
    }
  }
}
