package com.customjar.security.dto;

import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.Map;

@NoArgsConstructor
@ToString
@Data
public class AccessTokenInfoDto {
//    private String user;
    private Map claimsData;
    private String status;
    private String message;
}
