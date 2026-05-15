package pl.akmf.ksef.sdk.util;

import pl.akmf.ksef.sdk.api.KsefApiProperties;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class ExampleApiProperties extends KsefApiProperties {

    @Override
    public String getBaseUri() {
        return "https://api-test.ksef.mf.gov.pl"; // test
//        return "https://api-demo.ksef.mf.gov.pl"; // demo
//        return "https://api.ksef.mf.gov.pl"; // prod
    }

    @Override
    public Duration getRequestTimeout() {
        return Duration.ofSeconds(100);
    }

    @Override
    public Map<String, String> getDefaultHeaders() {
        Map<String, String> headers = new HashMap<>();

        return headers;
    }
}
