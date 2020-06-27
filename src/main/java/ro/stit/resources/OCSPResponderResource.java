package ro.stit.resources;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;

import javax.inject.Inject;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.micronaut.http.annotation.Body;
import io.micronaut.http.annotation.Consumes;
import io.micronaut.http.annotation.Controller;
import io.micronaut.http.annotation.Get;
import io.micronaut.http.annotation.PathVariable;
import io.micronaut.http.annotation.Post;
import io.micronaut.http.annotation.Produces;
import ro.stit.conf.OCSPResponderConf;
import ro.stit.dto.CertificateSummary;
import ro.stit.dto.OCSPCertificateStatusWrapper;
import ro.stit.dto.RevocationReason;
import ro.stit.service.CertificateManager;
import ro.stit.service.OCSPResponderService;

@Controller
@Produces("application/ocsp-response")
public class OCSPResponderResource {
  public static final Logger LOG = LoggerFactory.getLogger(OCSPResponderResource.class);

  private final CertificateManager certificateManager;
  private final OCSPResponderService ocspResponderService;
  private final OCSPResponderConf ocspResponderConf;

  @Inject
  public OCSPResponderResource(final CertificateManager certificateManager,
      final OCSPResponderService ocspResponderService, final OCSPResponderConf ocspResponderConf) {
    this.certificateManager = certificateManager;
    this.ocspResponderService = ocspResponderService;
    this.ocspResponderConf = ocspResponderConf;
  }

  /***
   * OCSP request over http via GET method This method will parse the param and
   * return 400 if it could not.
   *
   * @param urlEncodedOCSPRequest The url-safe, base64 encoded, der encoded, OCSP
   *                              request
   * @return The OCSP response
   */
  @Get("ocsp/{urlEncodedOCSPRequest}")
  public byte[] processGetRequest(
      @PathVariable("urlEncodedOCSPRequest") final String urlEncodedOCSPRequest) {
    OCSPReq ocspReq;
    final byte[] derEncodedOCSPRequest = Base64.getDecoder().decode(urlEncodedOCSPRequest);
    try {
      ocspReq = new OCSPReq(derEncodedOCSPRequest);
      return processOCSPRequest(ocspReq);
    } catch (final IOException e) {
      try {
        final var respBody = new OCSPRespBuilder().build(OCSPRespBuilder.MALFORMED_REQUEST, null);
        return respBody.getEncoded();
      } catch (final OCSPException | IOException e1) {
        throw new RuntimeException("Could not construct proper OCSP response", e1);
      }
    }

  }

  @Post("/")
  @Consumes("application/ocsp-request")
  public byte[] processPostRequest(@Body byte[] body) {
    LOG.warn("Received body: " + body.length);
    try {
      return processOCSPRequest(new OCSPReq(body));
    } catch (IOException e) {
      LOG.error("Cannot parse OCSPReq", e);
      throw new RuntimeException("Could not construct proper OCSP response", e);
    }
  }

  /**
   * Processes the OCSP request and catches any exceptions that occur to attempt
   * to return an INTERNAL_ERROR response. If it still can't do that, 500s.
   *
   * @param ocspReq
   * @return The OCSP response if possible
   */
  private byte[] processOCSPRequest(final OCSPReq ocspReq) {
    try {
      return doProcessOCSPRequest(ocspReq);
    } catch (final OCSPException | IOException e) {
      LOG.error("Error processing OCSP Request!", e);
      try {
        final var respBody = new OCSPRespBuilder().build(OCSPRespBuilder.INTERNAL_ERROR, null);
        return respBody.getEncoded();
      } catch (final OCSPException | IOException e1) {
        throw new RuntimeException("Could not construct proper OCSP response", e1);
      }
    }
  }

  /**
   * Processes the OCSP request from the client.
   *
   * According to <a href="https://tools.ietf.org/html/rfc6960">RFC 6960 </a> the
   * responder is tasked with the following checks and if any are not true, an
   * error message is returned:
   *
   * 1. the message is well formed 2. the responder is configured to provide the
   * requested service 3. the request contains the information needed by the
   * responder.
   *
   * If we are at this point, number one is taken care of (we were able to parse
   * it).
   *
   * This method will check the second and third conditions as well as do any
   * additional validation on the request before returning an OCSP response.
   *
   * @param ocspReq The OCSP request
   * @return The OCSP response
   * @throws IOException
   */

  private byte[] doProcessOCSPRequest(final OCSPReq ocspReq) throws OCSPException, IOException {
    final var responderId = ocspResponderService.extractRespId().orElseThrow();
    final var responseBuilder = new BasicOCSPRespBuilder(responderId);

    checkForValidRequest(ocspReq);

    // Add appropriate extensions
    var responseExtensions = new ArrayList<Extension>();

    // nonce
    var nonceExtension = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
    if (nonceExtension != null) {
      responseExtensions.add(nonceExtension);
    }

    if (ocspResponderConf.isRejectUnknown()) {
      responseExtensions.add(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_extended_revoke, false, new byte[] {}));
    }

    Extension[] extensions = responseExtensions.toArray(new Extension[responseExtensions.size()]);
    responseBuilder.setResponseExtensions(new Extensions(extensions));

    // Check if each request is valid and put the appropriate response in the
    // builder
    Req[] requests = ocspReq.getRequestList();
    for (Req request : requests) {
      addResponse(responseBuilder, request);
    }
    return buildAndSignResponse(responseBuilder);
  }

  private byte[] buildAndSignResponse(BasicOCSPRespBuilder responseBuilder) throws OCSPException, IOException {
    ContentSigner contentSigner = ocspResponderService.createSigner()
        .orElseThrow(() -> new OCSPException("Cannot create signer!"));
    var certificateChain = ocspResponderService
        .asBouncyCastleFormat(ocspResponderService.extractOCSPX509CertificateChain());
    var producedAt = Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC));

    var ocspRes = responseBuilder.build(contentSigner, certificateChain, producedAt);

    return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, ocspRes).getEncoded();
  }

  /**
   * Checks for a valid request and throws a OCSPException with the OCSP response
   * if not valid
   *
   * @param ocspReq The request
   * @throws OCSPException if request is malformed
   */
  private void checkForValidRequest(OCSPReq ocspReq) throws OCSPException {
    if (ocspReq == null) {
      throw new OCSPException("Ocsp request is missing");
    }

    // check signature if present
    if (ocspReq.isSigned() && !isSignatureValid(ocspReq)) {
      throw new OCSPException("Your signature was invalid");
    }
  }

  /**
   * Checks to see if signature in the OCSP request is valid.
   *
   * @param ocspReq The ocsp request
   * @return {@code true} if signature is valid, {@code false} otherwise.
   */
  private boolean isSignatureValid(OCSPReq ocspReq) throws OCSPException {
    try {
      var contentVerifierProvider = new JcaContentVerifierProviderBuilder().setProvider("BC")
          .build(ocspReq.getCerts()[0]);
      return ocspReq.isSignatureValid(contentVerifierProvider);
    } catch (CertificateException | OperatorCreationException e) {
      LOG.warn("Could not read signature", e);
      return false;
    }
  }

  private void addResponse(BasicOCSPRespBuilder responseBuilder, Req request) throws OCSPException {
    var certificateId = request.getCertID();

    // build extensions
    var extensions = new Extensions(new Extension[] {});
    var requestExtensions = request.getSingleRequestExtensions();
    if (requestExtensions != null) {
      var nonceExtension = requestExtensions.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
      if (nonceExtension != null) {
        extensions = new Extensions(nonceExtension);
      }
    }

    // check issuer
    var digestCalc = ocspResponderService.createDigestCalculator().orElseThrow();
    var issuingCertificate = ocspResponderService.getIssuingCertificate().orElseThrow();

    var matcherIssuer = certificateId.matchesIssuer(issuingCertificate, digestCalc);

    if (!matcherIssuer) {
      addResponseForCertificateRequest(responseBuilder, certificateId,
          new OCSPCertificateStatusWrapper(getUnknownStatus(), LocalDateTime.now(),
              LocalDateTime.now().plusSeconds(certificateManager.getRefreshSeconds())),
          extensions);
    } else {
      var certificateSummary = certificateManager.getSummary(certificateId.getSerialNumber());

      addResponseForCertificateRequest(responseBuilder, request.getCertID(),
          getOCSPCertificateStatus(certificateSummary), extensions);
    }
  }

  private void addResponseForCertificateRequest(BasicOCSPRespBuilder responseBuilder, CertificateID certificateId,
      OCSPCertificateStatusWrapper status, Extensions extensions) {
    responseBuilder.addResponse(certificateId, status.getCertificateStatus(), status.getThisUpdateDate(),
        status.getNextUpdateDate(), extensions);
  }

  /**
   * Gets the OCSP Certificate Status wrapper with the Certificate Status (good,
   * revoked, unknown), the updated date, and the next update date.
   *
   * @param summary The certificate summary
   * @return The status wrapper
   */
  private OCSPCertificateStatusWrapper getOCSPCertificateStatus(CertificateSummary summary) {
    CertificateStatus status;
    switch (summary.getStatus()) {
      case VALID:
        status = CertificateStatus.GOOD;
        break;
      case REVOKED:
        status = new RevokedStatus(summary.getRevocationTimeDate(), summary.getRevocationReason().getCode());
        break;
      case EXPIRED:
        status = new RevokedStatus(summary.getExpirationTimeDate(), RevocationReason.SUPERSEDED.getCode());
        break;
      case UNKNOWN:
        status = getUnknownStatus();
        break;
      default:
        throw new IllegalArgumentException("Unknown status!" + summary.getStatus().name());
    }
    LocalDateTime updateTime = summary.getThisUpDateTime();
    return new OCSPCertificateStatusWrapper(status, updateTime,
        updateTime.plusSeconds(certificateManager.getRefreshSeconds()));
  }

  /**
   * Gets the unknown CertificateStatus to return depending on the value of
   * {@code rejectUnknown}
   *
   * @return The CertificateStatus to use for unknown certificates
   */
  private CertificateStatus getUnknownStatus() {
    if (ocspResponderConf.isRejectUnknown()) {
      var nowDate = Date.from(LocalDateTime.now().toInstant(ZoneOffset.UTC));
      return new RevokedStatus(nowDate, RevocationReason.UNSPECIFIED.getCode());
    } else {
      return new UnknownStatus();
    }
  }

}
