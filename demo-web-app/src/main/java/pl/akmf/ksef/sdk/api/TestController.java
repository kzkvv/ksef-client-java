package pl.akmf.ksef.sdk.api;

import jakarta.xml.bind.JAXBException;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.retry.annotation.Backoff;
import org.springframework.retry.annotation.Recover;
import org.springframework.retry.annotation.Retryable;
import org.springframework.web.bind.annotation.*;
import pl.akmf.ksef.sdk.api.builders.auth.AuthTokenRequestBuilder;
import pl.akmf.ksef.sdk.api.builders.auth.AuthTokenRequestSerializer;
import pl.akmf.ksef.sdk.api.builders.certificate.CertificateBuilders;
import pl.akmf.ksef.sdk.client.interfaces.CertificateService;
import pl.akmf.ksef.sdk.client.interfaces.SignatureService;
import pl.akmf.ksef.sdk.client.model.ApiException;
import pl.akmf.ksef.sdk.client.model.auth.*;
import pl.akmf.ksef.sdk.client.model.certificate.SelfSignedCertificate;
import pl.akmf.ksef.sdk.client.model.session.online.OpenOnlineSessionResponse;
import pl.akmf.ksef.sdk.client.model.session.online.SendInvoiceResponse;
import pl.akmf.ksef.sdk.client.model.xml.AuthTokenRequest;
import pl.akmf.ksef.sdk.client.model.xml.SubjectIdentifierTypeEnum;
import pl.akmf.ksef.sdk.exception.StatusWaitingException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static pl.akmf.ksef.sdk.client.Headers.AUTHORIZATION;

@Slf4j
@RestController
@RequiredArgsConstructor
public class TestController {
    private final DefaultKsefClient ksefClient;
    private final SignatureService signatureService;
    private final CertificateService certificateService;

    private final AuthController authController;
    private final OnlineSessionController onlineSessionController;

    @SneakyThrows
    @GetMapping(value = "sample-incoming-cert")
    public CertAuthRequest prepareSampleCertAuthRequest(
            @RequestParam String sellerNip,
            @RequestParam String buyerNip
    ) throws CertificateEncodingException {
        CertificateBuilders.X500NameHolder x500 = new CertificateBuilders()
                .buildForOrganization("Kowalski sp. z o.o", "VATPL-" + sellerNip, "Kowalski", "PL");
        SelfSignedCertificate selfSignedCertificate = certificateService.generateSelfSignedCertificateRsa(x500);
        String privateKeyBase64 = Base64.getEncoder().encodeToString(selfSignedCertificate.getPrivateKey().getEncoded());
        String certInBase64 = Base64.getEncoder().encodeToString(selfSignedCertificate.certificate().getEncoded());
        CertAuthRequest certAuthRequest = new CertAuthRequest();
        certAuthRequest.certInBase64 = certInBase64;
        certAuthRequest.privateKeyBase64 = privateKeyBase64;
        certAuthRequest.contextIdentifier = sellerNip;

        log.info("Cert generated");

        AuthOperationStatusResponse authOperationStatusResponse = getAuthOperationStatusResponse(certAuthRequest);
        log.info("Auth operation status response: {}", authOperationStatusResponse);

        var authToken = authOperationStatusResponse.getAccessToken().getToken();

        OpenOnlineSessionResponse openOnlineSessionResponse = onlineSessionController.initSession(authToken);
        log.info("Open online session response: {}", openOnlineSessionResponse);

        SendInvoiceResponse sendInvoiceResponse = onlineSessionController.sendInvoiceOnlineSessionAsync(
                openOnlineSessionResponse.getReferenceNumber(),
                sellerNip,
                buyerNip,
                authToken
        );
        log.info("Send invoice response: {}", sendInvoiceResponse);

        onlineSessionController.sessionClose(
                openOnlineSessionResponse.getReferenceNumber(),
                authToken
        );

        log.info("Session closed");
        return certAuthRequest;
    }

//    @Retryable(
//            retryFor = {
//                    StatusWaitingException.class,
//            }, maxAttempts = 100,
//            recover = "recoverAuthReadyStatusCheck",
//            backoff = @Backoff(delay = 30)
//
//    )
    private AuthOperationStatusResponse getAuthOperationStatusResponse(CertAuthRequest certAuthRequest) throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, ApiException, JAXBException, IOException {
        return authController.authWithKsefCert(certAuthRequest);
    }

//    @Recover
//    public void recoverAuthReadyStatusCheck(String referenceNumber, String tempToken) throws ApiException {
//        AuthStatus authStatus = ksefClient.getAuthStatus(referenceNumber, tempToken);
//
//        if (authStatus.getStatus().getCode() != 200) {
//            log.error("Timeout for authentication process");
//            throw new StatusWaitingException("Authentication process has not been fineshed yet");
//        }
//    }


}
