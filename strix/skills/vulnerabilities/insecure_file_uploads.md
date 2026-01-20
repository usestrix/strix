---
name: insecure-file-uploads
description: File upload security testing covering extension bypass, content-type manipulation, and path traversal
---

# Insecure File Uploads

Upload surfaces are high risk: server-side execution (RCE), stored XSS, malware distribution, storage takeover, and DoS. Modern stacks mix direct-to-cloud uploads, background processors, and CDNs—authorization and validation must hold across every step.

## Attack Surface

- Web/mobile/API uploads, direct-to-cloud (S3/GCS/Azure) presigned flows, resumable/multipart protocols (tus, S3 MPU)
- Image/document/media pipelines (ImageMagick/GraphicsMagick, Ghostscript, ExifTool, PDF engines, office converters)
- Admin/bulk importers, archive uploads (zip/tar), report/template uploads, rich text with attachments
- Serving paths: app directly, object storage, CDN, email attachments, previews/thumbnails

## Reconnaissance

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

### Header and Render

- Missing X-Content-Type-Options: nosniff enabling browser sniff to script
- Content-Type reflection from upload vs server-set; Content-Disposition: inline vs attachment

### Process Side Effects

- AV/CDR race or absence; background job status allows access before scan completes; password-protected archives bypass scanning

## Core Payloads

### Web Shells and Configs

- PHP: GIF polyglot (starts with GIF89a) followed by `<?php echo 1; ?>`; place where PHP is executed
- .htaccess to map extensions to code (AddType/AddHandler); .user.ini (auto_prepend/append_file) for PHP-FPM
- ASP/JSP equivalents where supported; IIS web.config to enable script execution

### Stored XSS

- SVG with onload/onerror handlers served as image/svg+xml or text/html
- HTML file with script when served as text/html or sniffed due to missing nosniff

### MIME Magic Polyglots

- Double extensions: avatar.jpg.php, report.pdf.html; mixed casing: .pHp, .PhAr
- Magic-byte spoofing: valid JPEG header then embedded script; verify server uses content inspection, not extensions alone

### Archive Attacks

- Zip Slip: entries with `../../` to escape extraction dir; symlink-in-zip pointing outside target; nested zips
- Zip bomb: extreme compression ratios to exhaust resources in processors

### Toolchain Exploits

- ImageMagick/GraphicsMagick legacy vectors (policy.xml may mitigate): crafted SVG/PS/EPS invoking external commands or reading files
- Ghostscript in PDF/PS with file operators (%pipe%)
- ExifTool metadata parsing bugs; overly large or crafted EXIF/IPTC/XMP fields

### Cloud Storage Vectors

- S3/GCS presigned uploads: attacker controls Content-Type/Disposition; set text/html or image/svg+xml and inline rendering
- Public-read ACL or permissive bucket policies expose uploads broadly
- Object key injection via user-controlled path prefixes
- Signed URL reuse and stale URLs; serving directly from bucket without attachment + nosniff headers

## Advanced Techniques

### Resumable Multipart

- Change metadata between init and complete (e.g., swap Content-Type/Disposition at finalize)
- Upload benign chunks, then swap last chunk or complete with different source

### Filename and Path

- Unicode homoglyphs, trailing dots/spaces, device names, reserved characters to bypass validators
- Null-byte truncation on legacy stacks; overlong paths; case-insensitive collisions overwriting existing files

### Processing Races

- Request file immediately after upload but before AV/CDR completes
- Trigger heavy conversions (large images, deep PDFs) to widen race windows

### Metadata Abuse

- Oversized EXIF/XMP/IPTC blocks to trigger parser flaws
- Payloads in document properties of Office/PDF rendered by previewers

### Header Manipulation

- Force inline rendering with Content-Type + inline Content-Disposition
- Cache poisoning via CDN with keys missing Vary on Content-Type/Disposition

## Bypass Techniques

### Validation Gaps

- Client-side only checks; relying on JS/MIME provided by browser
- Trusting multipart boundary part headers blindly
- Extension allowlists without server-side content inspection

### Evasion Tricks

- Double extensions, mixed case, hidden dotfiles, extra dots (file..png), long paths with allowed suffix
- Multipart name vs filename vs path discrepancies; duplicate parameters and late parameter precedence

## Special Contexts

### Rich Text Editors

- RTEs allow image/attachment uploads and embed links; verify sanitization and serving headers

### Mobile Clients

- Mobile SDKs may send nonstandard MIME or metadata; servers sometimes trust client-side transformations

### Serverless and CDN

- Direct-to-bucket uploads with Lambda/Workers post-processing; verify security decisions are not delegated to frontends
- CDN caching of uploaded content; ensure correct cache keys and headers

## Testing Methodology

1. **Map the pipeline** - Client → ingress → storage → processors → serving. Note where validation and auth occur
2. **Identify allowed types** - Size limits, filename rules, storage keys, and who serves the content
3. **Collect baselines** - Capture resulting URLs and headers for legitimate uploads
4. **Exercise bypass families** - Extension games, MIME/content-type, magic bytes, polyglots, metadata payloads, archive structure
5. **Validate execution** - Can uploaded content execute on server or client?

## Validation

1. Demonstrate execution or rendering of active content: web shell reachable, or SVG/HTML executing JS when viewed
2. Show filter bypass: upload accepted despite restrictions with evidence on retrieval
3. Prove header weaknesses: inline rendering without nosniff or missing attachment
4. Show race or pipeline gap: access before AV/CDR; extraction outside intended directory
5. Provide reproducible steps: request/response for upload and subsequent access

## False Positives

- Upload stored but never served back; or always served as attachment with strict nosniff
- Converters run in locked-down sandboxes with no external IO and no script engines
- AV/CDR blocks the payload and quarantines; access before scan is impossible by design

## Impact

- Remote code execution on application stack or media toolchain host
- Persistent cross-site scripting and session/token exfiltration via served uploads
- Malware distribution via public storage/CDN; brand/reputation damage
- Data loss or corruption via overwrite/zip slip; service degradation via zip bombs

## Pro Tips

1. Keep PoCs minimal: tiny SVG/HTML for XSS, a single-line PHP/ASP where relevant
2. Always capture download response headers and final MIME; that decides browser behavior
3. Prefer transforming risky formats to safe renderings (SVG→PNG) rather than complex sanitization
4. In presigned flows, constrain all headers and object keys server-side
5. For archives, extract in a chroot/jail with explicit allowlist; drop symlinks and reject traversal
6. Test finalize/complete steps in resumable flows; many validations only run on init
7. Verify background processors with EICAR and tiny polyglots
8. When you cannot get execution, aim for stored XSS or header-driven script execution
9. Validate that CDNs honor attachment/nosniff
10. Document full pipeline behavior per asset type

## Summary

Secure uploads are a pipeline property. Enforce strict type, size, and header controls; transform or strip active content; never execute or inline-render untrusted uploads; and keep storage private with controlled, signed access.
