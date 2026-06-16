import xml.etree.ElementTree as ET

# ruleid: py-xxe
def bad(user_xml):
    tree = ET.parse(user_xml)
    return tree

# ok: py-xxe
def good(user_xml):
    import defusedxml.ElementTree as SafeET
    tree = SafeET.parse(user_xml)
    return tree
