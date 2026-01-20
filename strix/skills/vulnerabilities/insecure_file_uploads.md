# INSECURE FILE UPLOADS

## Critical

Upload surfaces are high risk: server-side execution (RCE), stored XSS, malware distribution, storage takeover, and DoS. Modern stacks mix direct-to-cloud uploads, background processors, and CDNs—authorization and validation must hold across every step.

## Scope

- Web/mobile/API uploads, direct-to-cloud (S3/GCS/Azure) presigned flows, resumable/multipart protocols (tus, S3 MPU)
- Image/document/media pipelines (ImageMagick/GraphicsMagick, Ghostscript, ExifTool, PDF engines, office converters)
- Admin/bulk importers, archive uploads (zip/tar), report/template uploads, rich text with attachments
- Serving paths: app directly, object storage, CDN, email attachments, previews/thumbnails

## Methodology

1. Map the pipeline: client → ingress (edge/app/gateway) → storage → processors (thumb, OCR, AV, CDR) → serving (app/storage/CDN). Note where validation and auth occur.
2. Identify allowed types, size limits, filename rules, storage keys, and who serves the content. Collect baseline uploads per type and capture resulting URLs and headers.
3. Exercise bypass families systematically: extension games, MIME/content-type, magic bytes, polyglots, metadata payloads, archive structure, chunk/finalize differentials.
4. Validate execution and rendering: can uploaded content execute on server or client? Confirm with minimal PoCs and headers analysis.

## Discovery Techniques

### Surface Map

- Endpoints/fields: upload, file, avatar, image, attachment, import, media, document, template
- Direct-to-cloud params: key, bucket, acl, Content-Type, Content-Disposition, x-amz-meta-*, cache-control
- Resumable APIs: create/init → upload/chunk → complete/finalize; check if metadata/headers can be altered late
- Background processors: thumbnails, PDF→image, virus scan queues; identify timing and status transitions

### Capability Probes

- Small probe files of each claimed type; diff resulting Content-Type, Content-Disposition, and X-Content-Type-Options on download
- Magic bytes vs extension: JPEG/GIF/PNG headers; mismatches reveal reliance on extension or MIME sniffing
- SVG/HTML probe: do they render inline (text/html or image/svg+xml) or download (attachment)?
- Archive probe: simple zip with nested path traversal entries and symlinks to detect extraction rules

## Detection Channels

### Server Execution

- Web shell execution (language dependent), config/handler uploads (.htaccess, .user.ini, web.config) enabling execution
- Interpreter-side template/script evaluation during conversion (ImageMagick/Ghostscript/ExifTool)

### Client Execution

- Stored XSS via SVG/HTML/JS if served inline without correct headers; PDF JavaScript; office macros in previewers

### Header And Render

- Missing X-Content-Type-Options: nosniff enabling browser sniff to script
- Content-Type reflection from upload vs server-set; Content-Disposition: inline vs attachment

### Process Side Effects

- AV/CDR race or absence; background job status allows access before scan completes; password-protected archives bypass scanning

## Core Payloads

### Web Shells And Configs

- PHP: GIF polyglot (starts with GIF89a) followed by <?php echo 1; ?>; place where PHP is executed
- .htaccess to map extensions to code (AddType/AddHandler); .user.ini (auto_prepend/append_file) for PHP-FPM
- ASP/JSP equivalents where supported; IIS web.config to enable script execution

### Stored Xss

- SVG with onload/onerror handlers served as image/svg+xml or text/html
- HTML file with script when served as text/html or sniffed due to missing nosniff

### Mime Magic Polyglots

- Double extensions: avatar.jpg.php, report.pdf.html; mixed casing: .pHp, .PhAr
- Magic-byte spoofing: valid JPEG header then embedded script; verify server uses content inspection, not extensions alone

### Archive Attacks

- Zip Slip: entries with ../../ to escape extraction dir; symlink-in-zip pointing outside target; nested zips
- Zip bomb: extreme compression ratios (e.g., 42.zip) to exhaust resources in processors

### Toolchain Exploits

- ImageMagick/GraphicsMagick legacy vectors (policy.xml may mitigate): crafted SVG/PS/EPS invoking external commands or reading files
- Ghostscript in PDF/PS with file operators (%pipe%)
- ExifTool metadata parsing bugs; overly large or crafted EXIF/IPTC/XMP fields

### Cloud Storage Vectors

- S3/GCS presigned uploads: attacker controls Content-Type/Disposition; set text/html or image/svg+xml and inline rendering
- Public-read ACL or permissive bucket policies expose uploads broadly; object key injection via user-controlled path prefixes
- Signed URL reuse and stale URLs; serving directly from bucket without attachment + nosniff headers

## Advanced Techniques

### Resumable Multipart

- Change metadata between init and complete (e.g., swap Content-Type/Disposition at finalize)
- Upload benign chunks, then swap last chunk or complete with different source if server trusts client-side digests only

### Filename And Path

- Unicode homoglyphs, trailing dots/spaces, device names, reserved characters to bypass validators and filesystem rules
- Null-byte truncation on legacy stacks; overlong paths; case-insensitive collisions overwriting existing files

### Processing Races

- Request file immediately after upload but before AV/CDR completes; or during derivative creation to get unprocessed content
- Trigger heavy conversions (large images, deep PDFs) to widen race windows

### Metadata Abuse

- Oversized EXIF/XMP/IPTC blocks to trigger parser flaws; payloads in document properties of Office/PDF rendered by previewers

### Header Manipulation

- Force inline rendering with Content-Type + inline Content-Disposition; test browsers with and without nosniff
- Cache poisoning via CDN with keys missing Vary on Content-Type/Disposition

## Filter Bypasses

### Validation Gaps

- Client-side only checks; relying on JS/MIME provided by browser; trusting multipart boundary part headers blindly
- Extension allowlists without server-side content inspection; magic-bytes only without full parsing

### Evasion Tricks

- Double extensions, mixed case, hidden dotfiles, extra dots (file..png), long paths with allowed suffix
- Multipart name vs filename vs path discrepancies; duplicate parameters and late parameter precedence

## Special Contexts

### Rich Text Editors

- RTEs allow image/attachment uploads and embed links; verify sanitization and serving headers for embedded content

### Mobile Clients

- Mobile SDKs may send nonstandard MIME or metadata; servers sometimes trust client-side transformations or EXIF orientation

### Serverless And Cdn

- Direct-to-bucket uploads with Lambda/Workers post-processing; verify that security decisions are not delegated to frontends
- CDN caching of uploaded content; ensure correct cache keys and headers (attachment, nosniff)

## Parser Hardening

- Validate on server: strict allowlist by true type (parse enough to confirm), size caps, and structural checks (dimensions, page count)
- Strip active content: convert SVG→PNG; remove scripts/JS from PDF; disable macros; normalize EXIF; consider CDR for risky types
- Store outside web root; serve via application or signed, time-limited URLs with Content-Disposition: attachment and X-Content-Type-Options: nosniff
- For cloud: private buckets, per-request signed GET, enforce Content-Type/Disposition on GET responses from your app/gateway
- Disable execution in upload paths; ignore .htaccess/.user.ini; sanitize keys to prevent path injections; randomize filenames
- AV + CDR: scan synchronously when possible; quarantine until verdict; block password-protected archives or process in sandbox

## Validation

1. Demonstrate execution or rendering of active content: web shell reachable, or SVG/HTML executing JS when viewed.
2. Show filter bypass: upload accepted despite restrictions (extension/MIME/magic mismatch) with evidence on retrieval.
3. Prove header weaknesses: inline rendering without nosniff or missing attachment; present exact response headers.
4. Show race or pipeline gap: access before AV/CDR; extraction outside intended directory; derivative creation from malicious input.
5. Provide reproducible steps: request/response for upload and subsequent access, with minimal PoCs.

## False Positives

- Upload stored but never served back; or always served as attachment with strict nosniff
- Converters run in locked-down sandboxes with no external IO and no script engines; no path traversal on archive extraction
- AV/CDR blocks the payload and quarantines; access before scan is impossible by design

## Impact

- Remote code execution on application stack or media toolchain host
- Persistent cross-site scripting and session/token exfiltration via served uploads
- Malware distribution via public storage/CDN; brand/reputation damage
- Data loss or corruption via overwrite/zip slip; service degradation via zip bombs or oversized assets

## Pro Tips

1. Keep PoCs minimal: tiny SVG/HTML for XSS, a single-line PHP/ASP where relevant, and benign magic-byte polyglots.
2. Always capture download response headers and final MIME from the server/CDN; that decides browser behavior.
3. Prefer transforming risky formats to safe renderings (SVG→PNG) rather than attempting complex sanitization.
4. In presigned flows, constrain all headers and object keys server-side; ignore client-supplied ACL and metadata.
5. For archives, extract in a chroot/jail with explicit allowlist; drop symlinks and reject traversal.
6. Test finalize/complete steps in resumable flows; many validations only run on init, not at completion.
7. Verify background processors with EICAR and tiny polyglots; ensure quarantine gates access until safe.
8. When you cannot get execution, aim for stored XSS or header-driven script execution; both are impactful.
9. Validate that CDNs honor attachment/nosniff and do not override Content-Type/Disposition.
10. Document full pipeline behavior per asset type; defenses must match actual processors and serving paths.

## Remember

Secure uploads are a pipeline property. Enforce strict type, size, and header controls; transform or strip active content; never execute or inline-render untrusted uploads; and keep storage private with controlled, signed access.
