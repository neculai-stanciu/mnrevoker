package ro.stit;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import ro.stit.dto.CertificateSummary;

public class DateUpdaterFormatTest {

  @Test
  @DisplayName("Date should be accepted")
  public void testDateFormat() {
    final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern("yyMMddHHmmssX");
    var dateTime = LocalDateTime.parse("161226225718Z", DATE_TIME_FORMATTER);
    assertNotNull(dateTime);
  }

  @Test
  @DisplayName("CertificateSummary DATE formatter should parse ok")
  public void parseDateWithSummaryFormatter() {
    LocalDateTime.parse("161226225718Z", CertificateSummary.DATE_TIME_FORMATTER);
  }
  
}
