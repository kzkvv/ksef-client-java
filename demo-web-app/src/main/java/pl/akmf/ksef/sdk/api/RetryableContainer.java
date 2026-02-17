package pl.akmf.ksef.sdk.api;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.EnableRetry;
import org.springframework.retry.annotation.Recover;
import org.springframework.retry.annotation.Retryable;
import org.springframework.stereotype.Component;
import pl.akmf.ksef.sdk.client.model.ApiException;
import pl.akmf.ksef.sdk.client.model.auth.AuthStatus;
import pl.akmf.ksef.sdk.exception.StatusWaitingException;

@EnableRetry
@Slf4j
@Component
@RequiredArgsConstructor
public class RetryableContainer {

    private final DefaultKsefClient ksefClient;

    @Retryable(
            retryFor = {
                    StatusWaitingException.class,
            }, maxAttempts = 100,
            recover = "recoverAuthReadyStatusCheck",
            backoff = @Backoff(delay = 10)

    )
    public void isAuthStatusReady(String referenceNumber, String tempToken) throws ApiException {

        AuthStatus authStatus = ksefClient.getAuthStatus(referenceNumber, tempToken);

        if (authStatus.getStatus().getCode() != 200) {
            throw new StatusWaitingException("Authentication process has not been finished yet");
        }
    }

    @Recover
    public void recoverAuthReadyStatusCheck(String referenceNumber, String tempToken) throws ApiException {
        AuthStatus authStatus = ksefClient.getAuthStatus(referenceNumber, tempToken);

        if (authStatus.getStatus().getCode() != 200) {
            log.error("Timeout for authentication process");
            throw new StatusWaitingException("Authentication process has not been fineshed yet");
        }
    }

}
