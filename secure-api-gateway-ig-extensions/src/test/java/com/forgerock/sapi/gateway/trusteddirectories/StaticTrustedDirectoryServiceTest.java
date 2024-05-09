/*
 * Copyright © 2020-2024 ForgeRock AS (obst@forgerock.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.forgerock.sapi.gateway.trusteddirectories;

import static com.forgerock.sapi.gateway.trusteddirectories.FetchTrustedDirectoryFilterTest.createApiClient;
import static com.forgerock.sapi.gateway.trusteddirectories.TrustedDirectoryHeapletTest.createConfigForTrustedDirectoryWithJwksUri;
import static org.assertj.core.api.Assertions.assertThat;
import static org.forgerock.json.JsonValue.array;
import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.util.Map;

import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.forgerock.sapi.gateway.dcr.models.ApiClient;
import com.forgerock.sapi.gateway.trusteddirectories.StaticTrustedDirectoryService.Heaplet;

@ExtendWith(MockitoExtension.class)
class StaticTrustedDirectoryServiceTest {

    private static final String OB_DIR_ISSUER = "OpenBanking Directory";
    private static final String CDR_DIR_ISSUER = "CDR Directory";
    private static final String DEV_TEST_DIR_ISSUER = "Development Trusted Directory";
    private static final String DISABLED_DIR_ISSUER = "Disabled Directory";

    @Mock
    private TrustedDirectory openBankingDirectory;

    @Mock
    private TrustedDirectory cdrDirectory;

    @Mock
    private TrustedDirectory devTestDirectory;

    @Mock
    private TrustedDirectory disabledDirectory;

    private Map<String, TrustedDirectory> directoryConfig;
    private StaticTrustedDirectoryService directoryService;

    @BeforeEach
    public void beforeEach() {
        this.directoryConfig = Map.of(OB_DIR_ISSUER, openBankingDirectory,
                                      CDR_DIR_ISSUER, cdrDirectory,
                                      DEV_TEST_DIR_ISSUER, devTestDirectory,
                                      DISABLED_DIR_ISSUER, disabledDirectory);

        this.directoryService = new StaticTrustedDirectoryService(directoryConfig);
    }

    @Test
    void findDirectoriesByIssuerName() {
        directoryConfig.forEach((issuer, directory) ->
                assertThat(directoryService.getTrustedDirectoryConfiguration(issuer)).isSameAs(directory));
    }

    @Test
    void failsToFindDirectoryByIssuerNameIfIssuerDoesNotExist() {
        assertThat(directoryService.getTrustedDirectoryConfiguration("New Directory")).isNull();
    }

    @Test
    void failsToFindDirectoryIfDisabled() {
        when(disabledDirectory.isDisabled()).thenReturn(true);
        assertThat(directoryService.getTrustedDirectoryConfiguration(DISABLED_DIR_ISSUER)).isNull();
    }

    @Test
    void findDirectoriesByApiClient() {
        directoryConfig.forEach((issuer, directory) -> {
            final ApiClient apiClient = createApiClient(issuer);
            assertThat(directoryService.getTrustedDirectoryConfiguration(apiClient)).isSameAs(directory);
        });
    }

    @Test
    void failsToFindDirectoryByApiClientIfIssuerDoesNotExist() {
        assertThat(directoryService.getTrustedDirectoryConfiguration(createApiClient("New Directory"))).isNull();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void failsToConstructStaticTrustedDirectoryService(Map<String, TrustedDirectory> trustedDirectoryMap) {
        final IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new StaticTrustedDirectoryService(trustedDirectoryMap));

        assertThat(ex.getMessage()).isEqualTo("trustedDirectories configuration must not be null or empty");
    }

    @Nested
    class HeapletTests {

        @Test
        void shouldCreateDirectoryService() throws Exception {
            final HeapImpl heap = new HeapImpl(Name.of("heap"));
            final Heaplet heaplet = new Heaplet();

            final JsonValue obDirectoryConfig = createConfigForTrustedDirectoryWithJwksUri().put("issuer", OB_DIR_ISSUER);
            final JsonValue cdrDirectoryConfig = createConfigForTrustedDirectoryWithJwksUri().put("issuer", CDR_DIR_ISSUER);
            final JsonValue disabledDirectoryConfig = createConfigForTrustedDirectoryWithJwksUri().put("issuer", DISABLED_DIR_ISSUER);
            disabledDirectoryConfig.put("disabled", true);

            final JsonValue config = json(object(
                    field("trustedDirectories", array(wrapDirectoryConfigWithHeaplet(obDirectoryConfig),
                                                      wrapDirectoryConfigWithHeaplet(cdrDirectoryConfig),
                                                      wrapDirectoryConfigWithHeaplet(disabledDirectoryConfig)))));

            final StaticTrustedDirectoryService staticTrustedDirectoryService =
                    (StaticTrustedDirectoryService) heaplet.create(Name.of("test"), config, heap);

            final TrustedDirectory obDirectory = staticTrustedDirectoryService.getTrustedDirectoryConfiguration(OB_DIR_ISSUER);
            assertThat(obDirectory.getIssuer()).isEqualTo(OB_DIR_ISSUER);
            assertThat(obDirectory.isDisabled()).isFalse();

            final TrustedDirectory cdrDirectory = staticTrustedDirectoryService.getTrustedDirectoryConfiguration(CDR_DIR_ISSUER);
            assertThat(cdrDirectory.getIssuer()).isEqualTo(CDR_DIR_ISSUER);
            assertThat(cdrDirectory.isDisabled()).isFalse();

            assertThat(staticTrustedDirectoryService.getTrustedDirectoryConfiguration(DISABLED_DIR_ISSUER)).isNull();
            assertThat(staticTrustedDirectoryService.getTrustedDirectoryConfiguration("New Directory")).isNull();
        }

        private static JsonValue wrapDirectoryConfigWithHeaplet(JsonValue dirConfig) {
            return json(object(field("name", "TrustedDirectory"),
                               field("type", "TrustedDirectory"),
                               field("config", dirConfig)));
        }

    }

}