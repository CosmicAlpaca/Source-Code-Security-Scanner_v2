import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.XMLConstants;

public class XxeTest {
    public void bad(String xmlData) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // ruleid: java-xxe
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(xmlData);
    }

    public void good() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // ok: java-xxe
        // (builder not created — feature-only setup for illustration)
    }
}
