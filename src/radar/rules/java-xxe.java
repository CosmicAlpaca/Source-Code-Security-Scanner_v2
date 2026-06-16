import javax.xml.parsers.DocumentBuilderFactory;

class Bad {
    // ruleid: java-xxe
    void bad() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder();
    }

    // ok: java-xxe
    void good() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.newDocumentBuilder();
    }
}
