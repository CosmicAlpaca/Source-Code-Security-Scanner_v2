import javax.xml.parsers.DocumentBuilderFactory;

class TestXxe {
    void bad() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ruleid: java-xxe
        factory.newDocumentBuilder();
    }

    void good() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: java-xxe
        factory.newDocumentBuilder();
    }
}
