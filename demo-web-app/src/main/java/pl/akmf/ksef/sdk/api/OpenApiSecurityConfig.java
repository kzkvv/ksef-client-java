package pl.akmf.ksef.sdk;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiSecurityConfig {

    @Bean
    public OpenAPI api() {
        final String securitySchemeName = "authToken";

        return new OpenAPI()
                .components(new Components()
                        .addSecuritySchemes(securitySchemeName,
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.APIKEY)   // <− important
                                        .in(SecurityScheme.In.HEADER)       // header
                                        .name("Authorization")              // header name
                        ))
                // global security requirement -> applied to all operations unless overridden
                .addSecurityItem(new SecurityRequirement().addList(securitySchemeName));
    }
}
