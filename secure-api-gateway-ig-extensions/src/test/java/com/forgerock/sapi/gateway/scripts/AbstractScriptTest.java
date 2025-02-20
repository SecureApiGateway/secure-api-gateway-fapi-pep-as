/*
 * Copyright © 2020-2025 ForgeRock AS (obst@forgerock.com)
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
package com.forgerock.sapi.gateway.scripts;

import static org.forgerock.http.io.IO.newTemporaryStorage;
import static org.forgerock.openig.heap.Keys.CLIENT_HANDLER_HEAP_KEY;
import static org.forgerock.openig.heap.Keys.SCRIPT_FACTORY_MANAGER_HEAP_KEY;
import static org.forgerock.openig.heap.Keys.TEMPORARY_STORAGE_HEAP_KEY;

import java.io.File;
import java.nio.file.Paths;

import org.forgerock.http.Handler;
import org.forgerock.openig.config.env.DefaultEnvironment;
import org.forgerock.openig.heap.HeapImpl;
import org.forgerock.openig.heap.Name;
import org.forgerock.openig.script.DefaultScriptFactoryManager;
import org.forgerock.openig.script.GroovyScriptFactory;
import org.mockito.Mockito;

/**
 * Support testing and validation of Groovy scripts residing in {@code secure-api-gateway-core/config}.
 */
public abstract class AbstractScriptTest {

    protected static final String GROOVY_MIME_TYPE = "application/x-groovy";

    protected HeapImpl getHeap() throws Exception {
        final HeapImpl heap = new HeapImpl(Name.of("anonymous"));
        heap.put(TEMPORARY_STORAGE_HEAP_KEY, newTemporaryStorage());
        final DefaultScriptFactoryManager manager = new DefaultScriptFactoryManager();
        manager.registerFactory(new GroovyScriptFactory().init(new DefaultEnvironment(getScriptsDirectory())));
        heap.put(SCRIPT_FACTORY_MANAGER_HEAP_KEY, manager);
        heap.put(CLIENT_HANDLER_HEAP_KEY, Mockito.mock(Handler.class));
        return heap;
    }

    private static File getScriptsDirectory() {
        String sapigCoreFolder = Paths.get("..").toAbsolutePath().toString();
        String relativeScriptFolder = "config/7.3.0/fapi1part2adv/ig";
        String scriptsFolder = Paths.get(sapigCoreFolder, relativeScriptFolder).toAbsolutePath().toString();
        return new File(scriptsFolder);
   }
}
