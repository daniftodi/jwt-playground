package com.iftodi.jwt.playground;

import com.fasterxml.jackson.annotation.JsonProperty;

class NetSuiteRequest {
    private final String grantType = "client_credentials";
    private final String clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private final String clientAssertion;

    public NetSuiteRequest(String clientAssertion) {
        this.clientAssertion = clientAssertion;
    }

    @JsonProperty("grant_type")
    public String getGrantType() {
        return grantType;
    }

    @JsonProperty("client_assertion_type")
    public String getClientAssertionType() {
        return clientAssertionType;
    }

    @JsonProperty("client_assertion")
    public String getClientAssertion() {
        return clientAssertion;
    }
}
