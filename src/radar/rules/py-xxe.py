import xml.etree.ElementTree as ET

def bad(user_xml):
    # ruleid: py-xxe
    tree = ET.parse(user_xml)
    return tree

def good(safe_path):
    import defusedxml.ElementTree as SafeET
    # ok: py-xxe
    tree = SafeET.parse(safe_path)
    return tree
