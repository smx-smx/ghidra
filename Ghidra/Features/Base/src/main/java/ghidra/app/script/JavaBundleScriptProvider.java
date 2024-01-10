/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.script;

import generic.jar.ResourceFile;
import generic.stl.Pair;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.plugin.core.osgi.GhidraJarBundle;
import ghidra.app.plugin.core.osgi.GhidraSourceBundle;
import ghidra.app.plugin.core.osgi.OSGiParallelLock;
import ghidra.util.task.TaskMonitor;
import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.BundleWiring;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Stream;

public class JavaBundleScriptProvider extends GhidraScriptProvider {
    private final BundleHost bundleHost;

    public JavaBundleScriptProvider(){
        bundleHost = GhidraScriptUtil.getBundleHost();
    }
    @Override
    public String getDescription() {
        return "Java (JAR)";
    }

    @Override
    public String getExtension() {
        return ".jar";
    }

    /**
     * scans for Ghidra scripts in the default scripts package in the given bundle
     * @param bundle    the bundle to search in
     * @return          a collection of [Bundle, Class] pairs for each detected GhidraScript
     */
    private Stream<? extends Pair<Bundle, Class<?>>> collectClasses(Bundle bundle){
        var wiring = bundle.adapt(BundleWiring.class);
        return wiring.listResources("/", "*.class", BundleWiring.FINDENTRIES_RECURSE)
                .stream().filter(path -> bundle.getEntry(path) != null)
                .map(path -> {
                    // remove .class and convert to class name
                    return path.replace('/', '.').substring(0, path.length() - 6);
                })
                .map(it -> {
                    try {
                        return new Pair<Bundle, Class<?>>(bundle, bundle.loadClass(it));
                    } catch (ClassNotFoundException|NoClassDefFoundError e) {
                        e.printStackTrace();
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .filter(p -> {
                    return GhidraScript.class.isAssignableFrom(p.second);
                });
    }


    /**
     * Activate and build the {@link GhidraSourceBundle} containing {@code jarFile} then load the
     * script's class from its class loader.
     *
     * @param jarFile the source file
     * @param writer the target for build messages
     * @return the loaded {@link Class} object
     * @throws Exception if build, activation, or class loading fail
     */
    public Class<?> loadClass(ResourceFile jarFile, PrintWriter writer) throws Exception {
        GhidraJarBundle bundle = (GhidraJarBundle) bundleHost.getGhidraBundle(jarFile);
        if (bundle == null) {
            throw new ClassNotFoundException(
                    "Failed to find JAR bundle containing script: " + jarFile.toString());
        }

        bundleHost.activateAll(Collections.singletonList(bundle), TaskMonitor.DUMMY, writer);
        //String classname = bundle.classNameForScript(jarFile);
        Bundle osgiBundle = bundle.getOSGiBundle();
        if (osgiBundle == null) {
            throw new ClassNotFoundException(
                    "Failed to get OSGi bundle containing script: " + jarFile.toString());
        }
        var scriptClasses = collectClasses(osgiBundle);
        var scriptClass = scriptClasses.findFirst();
        if(!scriptClass.isPresent()){
            throw new RuntimeException("no script classes found in jar bundle");
        }
        Class<?> clazz = scriptClass.get().second;
        return clazz;
    }

    @Override
    public GhidraScript getScriptInstance(ResourceFile jarFile, PrintWriter writer) throws GhidraScriptLoadException {
        try (OSGiParallelLock lock = new OSGiParallelLock()) {
            Class<?> clazz = loadClass(jarFile, writer);

            if (GhidraScript.class.isAssignableFrom(clazz)) {
                GhidraScript script = (GhidraScript) clazz.getDeclaredConstructor().newInstance();
                script.setSourceFile(jarFile);
                return script;
            }

            throw new GhidraScriptLoadException(
                    "Ghidra scripts in Java must extend " + GhidraScript.class.getName() + ". " +
                            jarFile.getName() + " does not.");
        }
        catch (ClassNotFoundException e) {
            throw new GhidraScriptLoadException("The class could not be found. " +
                    "It must be the public class of the .java file: " + e.getMessage(), e);
        }
        catch (NoClassDefFoundError e) {
            throw new GhidraScriptLoadException("The class could not be found or loaded, " +
                    "perhaps due to a previous initialization error: " + e.getMessage(), e);
        }
        catch (ExceptionInInitializerError e) {
            throw new GhidraScriptLoadException(
                    "Error during class initialization: " + e.getException(), e.getException());
        }
        catch (InvocationTargetException e) {
            throw new GhidraScriptLoadException(
                    "Error during class construction: " + e.getTargetException(),
                    e.getTargetException());
        }
        catch (NoSuchMethodException e) {
            throw new GhidraScriptLoadException(
                    "The default constructor does not exist: " + e.getMessage(), e);
        }
        catch (IllegalAccessException e) {
            throw new GhidraScriptLoadException(
                    "The class or its default constructor is not accessible: " + e.getMessage(), e);
        }
        catch (Exception e) {
            throw new GhidraScriptLoadException("Unexpected error: " + e);
        }
    }

    @Override
    public void createNewScript(ResourceFile newScript, String category) throws IOException {
        throw new IOException("Java (JAR) scripts cannot be created in Ghidra");
    }

    @Override
    public String getCommentCharacter() {
        return "//";
    }
}
