package ro.stit.dto;

import javax.validation.constraints.NotEmpty;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CRLNameFilePair {

  @NotEmpty
  @JsonProperty
  private String name;

  @NotEmpty
  @JsonProperty
  private String filePath;

  public CRLNameFilePair() {
    //java bean convention
  }

  public CRLNameFilePair(String name, String filePath) {
    this.name = name;
    this.filePath = filePath;
  }
  public String getFilePath() {
    return filePath;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public void setFilePath(String filePath) {
    this.filePath = filePath;
  }
}
