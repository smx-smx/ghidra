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

import generic.jar.JarEntryFilter;
import generic.jar.ResourceFile;
import generic.stl.Pair;
import ghidra.app.plugin.core.osgi.*;
import ghidra.util.task.TaskMonitor;
import org.osgi.framework.Bundle;
import org.osgi.framework.wiring.BundleWiring;

import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;
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
     * scans for Ghidra scripts in the given bundle
     * @param osgiBundle    the bundle to search in
     * @return          a collection of [path, class] pairs for each detected GhidraScript
     */
    private static Stream<? extends Pair<String, Class<?>>> collectClasses(Bundle osgiBundle){
        var wiring = osgiBundle.adapt(BundleWiring.class);
        return wiring.listResources("/", "*.class", BundleWiring.FINDENTRIES_RECURSE)
                .stream().filter(path -> osgiBundle.getEntry(path) != null)
                .map(path -> {
                    // remove .class and convert to class name
                    var className = path.replace('/', '.').substring(0, path.length() - 6);
                    try {
                        var clazz = osgiBundle.loadClass(className);
                        return new Pair<String, Class<?>>(path, clazz);
                    } catch (ClassNotFoundException|NoClassDefFoundError e) {
                        return null;
                    }
                }).filter(it -> it != null && GhidraScript.class.isAssignableFrom(it.second));
    }

    @Override
    public boolean canLoadScript(ResourceFile scriptFile) {
        var resourcePath = scriptFile.getAbsolutePath();
        return resourcePath.endsWith(".jar") || resourcePath.startsWith(ResourceFile.JAR_FILE_PREFIX);
    }

    private void ensureBundleInstalled(GhidraJarBundle bundle) throws GhidraBundleException {
        var osgiBundle = bundle.getOSGiBundle();
        if(osgiBundle == null) {
            bundleHost.install(bundle);
        }
        if(!bundle.isEnabled()){
            bundleHost.enable(bundle);
        }
        bundleHost.activateAll(Collections.singleton(bundle), TaskMonitor.DUMMY, null);
    }

    private GhidraJarBundle getAndActivateJarBundle(ResourceFile container){
        var bundle = bundleHost.getGhidraBundle(container);
        if(bundle == null){
            bundle = bundleHost.add(container, true, false);
        }
        if(bundle instanceof GhidraJarBundle){
            try {
                ensureBundleInstalled((GhidraJarBundle) bundle);
            } catch (GhidraBundleException e) {
                throw new RuntimeException(e);
            }
            return (GhidraJarBundle) bundle;
        }
        return null;
    }

    private static final JarEntryFilter JAR_ENTRY_FILTER = jarEntry -> !jarEntry.isDirectory() && jarEntry.getName().endsWith(".class");

    @Override
    public Collection<ResourceFile> getNestedScripts(ResourceFile container) {
        var bundle = getAndActivateJarBundle(container);
        var osgiBundle = bundle.getOSGiBundle();

        var scriptClasses = collectClasses(osgiBundle)
                .map(it -> it.first)
                .collect(Collectors.toSet());

        var containerPath = container.getAbsolutePath();
        return scriptClasses.stream().map(it -> {
            var uri = String.format("%s//%s!/%s", ResourceFile.JAR_FILE_PREFIX, containerPath, it);
            return new ResourceFile(uri, JAR_ENTRY_FILTER);
        }).toList();
    }

    private ResourceFile getJarFile(ResourceFile jarFile){
        var absolutePath = jarFile.getAbsolutePath();
        if (absolutePath.startsWith(ResourceFile.JAR_FILE_PREFIX)) {
            int indexOf = absolutePath.indexOf("!/");
            if (indexOf < 0) {
                throw new IllegalArgumentException("Invalid jar specification: " + absolutePath);
            }
            String filePath = absolutePath.substring(ResourceFile.JAR_FILE_PREFIX.length(), indexOf);
            return new ResourceFile(filePath);
        }
        return jarFile;
    }

    /**
     * Activate and build the {@link GhidraSourceBundle} containing {@code jarFile} then load the
     * script's class from its class loader.
     *
     * @param resourceIdentifier the source file
     * @param writer the target for build messages
     * @return the loaded {@link Class} object
     * @throws Exception if build, activation, or class loading fail
     */
    public Class<?> loadClass(ResourceFile resourceIdentifier, PrintWriter writer) throws Exception {
        var className = getJarClassName(resourceIdentifier);
        var jarFile = getJarFile(resourceIdentifier);
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
        return osgiBundle.loadClass(className);
    }

    private static String getJarClassName(ResourceFile resource) {
        var absolutePath = resource.getAbsolutePath();
        if(!absolutePath.startsWith(ResourceFile.JAR_FILE_PREFIX)
        || !absolutePath.endsWith(".class")){
            throw new IllegalArgumentException("Invalid jar specification: " + absolutePath);
        }

        var indexOf = absolutePath.indexOf("!/");
        if(indexOf < 0){
            throw new IllegalArgumentException("Invalid jar specification: " + absolutePath);
        }
        var relaPath = absolutePath.substring(indexOf + 2, absolutePath.length() - 6);
        return relaPath.replace('/', '.');
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
