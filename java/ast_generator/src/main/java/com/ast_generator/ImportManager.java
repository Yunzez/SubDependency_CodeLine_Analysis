package com.ast_generator;

import java.util.HashSet;
import java.util.Set;

public class ImportManager {
    private Set<String> thirdPartyImports;

    public ImportManager() {
        this.thirdPartyImports = new HashSet<>();
    }

    public void addImports(Set<String> imports) {
        thirdPartyImports.addAll(imports);
    }

    public Set<String> getThirdPartyImports() {
        return thirdPartyImports;
    }

    // Additional methods as needed, such as clearImports, removeImport, etc.
}
