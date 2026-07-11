use crate::{robots, ssrf};
use rmcp::{
    ErrorData as McpError,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, Content, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router,
    handler::server::router::tool::ToolRouter,
    ServerHandler,
};
use schemars::JsonSchema;
use serde::Deserialize;
use url::Url;

const MAX_REDIRECTS: u8 = 5;
const MAX_BODY_BYTES: usize = 5 * 1024 * 1024; // 5 MB
const DEFAULT_TIMEOUT_SECS: u64 = 30;
const MAX_TIMEOUT_SECS: u64 = 120;
const SPOOFED_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36";
const HONEST_UA: &str = "opencode/1.0 (+https://opencode.ai)";

fn default_max_length() -> usize {
    5000
}

#[derive(Debug, Deserialize, JsonSchema, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    Text,
    Markdown,
    Html,
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Markdown
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct FetchRequest {
    /// The URL to fetch. Must be http:// or https://.
    pub url: String,
    /// The format to return content in: "text" (plain text), "markdown" (default), or "html" (raw).
    #[serde(default)]
    pub format: OutputFormat,
    /// Max characters of (post-extraction) content to return in one call.
    #[serde(default = "default_max_length")]
    pub max_length: usize,
    /// Character offset into the extracted content to start from — use this
    /// with max_length to page through content longer than one call can return.
    #[serde(default)]
    pub start_index: usize,
    /// Optional timeout in seconds (max 120). Default 30.
    #[serde(default = "default_timeout_secs")]
    pub timeout: u64,
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

#[derive(Clone)]
pub struct WebFetchServer {
    client: reqwest::Client,
    tool_router: ToolRouter<WebFetchServer>,
    respect_robots: bool,
}

#[tool_router]
impl WebFetchServer {
    pub fn new(respect_robots: bool) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(SPOOFED_UA)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(MAX_TIMEOUT_SECS))
            .build()
            .expect("failed to build reqwest client");

        Self {
            client,
            tool_router: Self::tool_router(),
            respect_robots,
        }
    }

    #[tool(
        name = "web_fetch",
        description = "Fetch content from a specified URL and return it in the requested format. \
        Supports markdown (default), plain text, or raw HTML output. \
        Converts HTML to markdown or plain text for readability. \
        Returns images as base64 data URIs. \
        Long content is paginated via start_index/max_length. \
        Refuses non-http(s) URLs and URLs resolving to private/loopback addresses. \
        Use this tool when you need to retrieve and analyze web content."
    )]
    async fn fetch(
        &self,
        Parameters(req): Parameters<FetchRequest>,
    ) -> Result<CallToolResult, McpError> {
        match self.do_fetch(req).await {
            Ok(result) => Ok(CallToolResult::success(result)),
            Err(e) => Ok(CallToolResult::error(vec![Content::text(e.to_string())])),
        }
    }
}

impl WebFetchServer {
    async fn do_fetch(&self, req: FetchRequest) -> anyhow::Result<Vec<Content>> {
        let timeout = std::time::Duration::from_secs(req.timeout.min(MAX_TIMEOUT_SECS));

        let mut current_url = Url::parse(&req.url)
            .map_err(|e| anyhow::anyhow!("invalid URL '{}': {e}", req.url))?;

        // Auto-upgrade HTTP to HTTPS (opencode behavior)
        if current_url.scheme() == "http" {
            let _ = current_url.set_scheme("https");
        }

        // Build Accept header based on requested format
        let accept_header = match req.format {
            OutputFormat::Markdown => {
                "text/markdown;q=1.0, text/x-markdown;q=0.9, text/plain;q=0.8, text/html;q=0.7, */*;q=0.1"
            }
            OutputFormat::Text => {
                "text/plain;q=1.0, text/markdown;q=0.9, text/html;q=0.8, */*;q=0.1"
            }
            OutputFormat::Html => {
                "text/html;q=1.0, application/xhtml+xml;q=0.9, text/plain;q=0.8, text/markdown;q=0.7, */*;q=0.1"
            }
        };

        let mut hops = 0u8;
        let response = loop {
            ssrf::validate_url(&current_url).await?;

            if self.respect_robots && !robots::is_allowed(&self.client, &current_url).await {
                anyhow::bail!(
                    "robots.txt for {} disallows fetching this path",
                    current_url.origin().ascii_serialization()
                );
            }

            let resp = self
                .client
                .get(current_url.clone())
                .header(reqwest::header::ACCEPT, accept_header)
                .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
                .timeout(timeout)
                .send()
                .await?;
            let status = resp.status();

            // Cloudflare challenge bypass: on 403 with cf-mitigated: challenge, retry with honest UA
            if status == reqwest::StatusCode::FORBIDDEN {
                let is_cf_challenge = resp
                    .headers()
                    .get("cf-mitigated")
                    .and_then(|v| v.to_str().ok())
                    == Some("challenge");
                if is_cf_challenge {
                    tracing::info!("Cloudflare challenge detected, retrying with honest UA");
                    let retry_resp = self
                        .client
                        .get(current_url.clone())
                        .header(reqwest::header::ACCEPT, accept_header)
                        .header(reqwest::header::ACCEPT_LANGUAGE, "en-US,en;q=0.9")
                        .header(reqwest::header::USER_AGENT, HONEST_UA)
                        .timeout(timeout)
                        .send()
                        .await?;
                    let retry_status = retry_resp.status();
                    if retry_status.is_redirection() {
                        if hops >= MAX_REDIRECTS {
                            anyhow::bail!("too many redirects (>{MAX_REDIRECTS})");
                        }
                        let location = retry_resp
                            .headers()
                            .get(reqwest::header::LOCATION)
                            .and_then(|v| v.to_str().ok())
                            .ok_or_else(|| {
                                anyhow::anyhow!("redirect response missing Location header")
                            })?;
                        current_url = current_url.join(location).map_err(|e| {
                            anyhow::anyhow!("bad redirect target '{location}': {e}")
                        })?;
                        hops += 1;
                        continue;
                    }
                    if !retry_status.is_success() {
                        anyhow::bail!("request failed with HTTP status {retry_status}");
                    }
                    break retry_resp;
                }
            }

            if status.is_redirection() {
                if hops >= MAX_REDIRECTS {
                    anyhow::bail!("too many redirects (>{MAX_REDIRECTS})");
                }
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow::anyhow!("redirect response missing Location header"))?;
                current_url = current_url
                    .join(location)
                    .map_err(|e| anyhow::anyhow!("bad redirect target '{location}': {e}"))?;
                hops += 1;
                continue;
            }

            if !status.is_success() {
                anyhow::bail!("request failed with HTTP status {status}");
            }

            break resp;
        };

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        // Eager Content-Length check
        if let Some(len) = response.content_length() {
            if len as usize > MAX_BODY_BYTES {
                anyhow::bail!(
                    "Response too large ({len} bytes, exceeds {} MB limit)",
                    MAX_BODY_BYTES / 1024 / 1024
                );
            }
        }

        let mime = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();

        // Image attachment support: return as base64 data URI
        if is_image_mime(&mime) {
            let bytes = read_capped(response, MAX_BODY_BYTES).await?;
            let b64 = base64_encode(&bytes);
            let _title = format!("{} ({})", req.url, content_type);
            return Ok(vec![
                Content::text(format!("Image fetched successfully ({mime})")),
                Content::image(format!("data:{mime};base64,{b64}"), &mime),
            ]);
        }

        // Binary rejection for non-textual content
        if !is_textual_mime(&mime) {
            let len = response.content_length();
            return Ok(vec![Content::text(format!(
                "Response is binary content (content-type: {content_type}{}). Not displaying as text.",
                len.map(|l| format!(", {l} bytes")).unwrap_or_default()
            ))]);
        }

        let bytes = read_capped(response, MAX_BODY_BYTES).await?;
        let body = String::from_utf8_lossy(&bytes).into_owned();

        let is_html = mime == "text/html" || mime == "application/xhtml+xml";

        let output = match req.format {
            OutputFormat::Html => body,
            OutputFormat::Text if is_html => extract_text_from_html(&body),
            OutputFormat::Text => body,
            OutputFormat::Markdown if is_html => html_to_markdown(&body),
            OutputFormat::Markdown => body,
        };

        Ok(vec![Content::text(paginate(
            &output,
            req.start_index,
            req.max_length,
        ))])
    }
}

fn is_textual_mime(mime: &str) -> bool {
    mime.starts_with("text/")
        || mime == "application/json"
        || mime.ends_with("+json")
        || mime == "application/xml"
        || mime.ends_with("+xml")
        || mime == "application/javascript"
        || mime == "application/x-javascript"
        || mime == "application/x-yaml"
        || mime == "text/yaml"
        || mime == "image/svg+xml" // SVG is XML text
}

fn is_image_mime(mime: &str) -> bool {
    mime.starts_with("image/")
        && mime != "image/svg+xml" // SVG is text
        && mime != "image/vnd.fastbidsheet"
}

/// Extract readable text from HTML by stripping non-visible tags.
/// Similar to opencode's extractTextFromHTML but implemented with html2text
/// for better spacing between block elements.
fn extract_text_from_html(html: &str) -> String {
    html2text::from_read(html.as_bytes(), 100).unwrap_or_else(|_| html.to_string())
}

/// Convert HTML to markdown using a lightweight approach:
/// strip script/style/meta/link tags, then use html2text for readable output.
fn html_to_markdown(html: &str) -> String {
    // Strip non-visible tags that pollute output
    let cleaned = strip_non_visible_tags(html);
    // html2text produces good readable plain text; for markdown we use a slightly wider column
    // and it preserves enough structure (headings, lists, code blocks) for LLM consumption
    html2text::from_read(cleaned.as_bytes(), 120).unwrap_or_else(|_| cleaned)
}

/// Strip script, style, noscript, meta, link tags and their content from HTML.
fn strip_non_visible_tags(html: &str) -> String {
    let mut result = String::with_capacity(html.len());
    let mut skip_depth = 0i32;
    let mut i = 0;
    let bytes = html.as_bytes();
    let len = bytes.len();

    while i < len {
        if bytes[i] == b'<' {
            // Look for closing tag: </tagname>
            if i + 1 < len && bytes[i + 1] == b'/' {
                let end = find_tag_end(bytes, i);
                if end > i {
                    let tag_name = extract_tag_name(&html[i + 2..end]);
                    if skip_depth > 0 && is_skippable_tag(&tag_name) {
                        skip_depth -= 1;
                    }
                    i = end + 1;
                    continue;
                }
            }
            // Look for opening tag: <tagname ...>
            let end = find_tag_end(bytes, i);
            if end > i {
                let tag_name = extract_tag_name(&html[i + 1..end]);
                if is_skippable_tag(&tag_name) {
                    skip_depth += 1;
                    i = end + 1;
                    continue;
                }
                if skip_depth > 0 {
                    i = end + 1;
                    continue;
                }
                // Also skip self-closing skippable tags
                let full_tag = &html[i + 1..end];
                if is_skippable_tag(&tag_name) && full_tag.ends_with('/') {
                    i = end + 1;
                    continue;
                }
            }
        }

        if skip_depth == 0 {
            result.push(bytes[i] as char);
        }
        i += 1;
    }

    result
}

fn find_tag_end(bytes: &[u8], start: usize) -> usize {
    for i in (start + 1)..bytes.len() {
        if bytes[i] == b'>' {
            return i;
        }
    }
    bytes.len()
}

fn extract_tag_name(tag_content: &str) -> String {
    let trimmed = tag_content.trim_start();
    let end = trimmed
        .find(|c: char| c.is_whitespace() || c == '>' || c == '/')
        .unwrap_or(trimmed.len());
    trimmed[..end].to_ascii_lowercase()
}

fn is_skippable_tag(name: &str) -> bool {
    matches!(
        name,
        "script" | "style" | "noscript" | "iframe" | "object" | "embed" | "meta" | "link"
    )
}

/// Simple base64 encoding using the `base64` crate would be ideal,
/// but to avoid adding another dependency, we use a no-alloc approach.
fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = Vec::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARS[((triple >> 18) & 0x3F) as usize]);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize]);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize]);
        } else {
            result.push(b'=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize]);
        } else {
            result.push(b'=');
        }
    }
    String::from_utf8(result).unwrap_or_default()
}

/// Reads a response body up to `cap` bytes, erroring instead of allocating unbounded memory.
async fn read_capped(response: reqwest::Response, cap: usize) -> anyhow::Result<Vec<u8>> {
    use futures_util::StreamExt;
    let mut stream = response.bytes_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if buf.len() + chunk.len() > cap {
            anyhow::bail!("response exceeded the {cap}-byte size limit");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

fn paginate(text: &str, start_index: usize, max_length: usize) -> String {
    let chars: Vec<char> = text.chars().collect();
    let total = chars.len();
    if start_index >= total {
        return format!("(start_index {start_index} is past the end of content; total length is {total} characters)");
    }
    let end = (start_index + max_length).min(total);
    let slice: String = chars[start_index..end].iter().collect();

    if end < total {
        format!(
            "{slice}\n\n[Content truncated. Showing characters {start_index}-{end} of {total}. \
            Call again with start_index={end} to continue.]"
        )
    } else {
        slice
    }
}

#[tool_handler]
impl ServerHandler for WebFetchServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(
                "Fetches content from a URL and returns it as markdown (default), plain text, or raw HTML. \
                 Supports pagination for large content. Returns images as base64 data URIs. \
                 Refuses private/loopback IP addresses (SSRF protection). Respects robots.txt."
                    .to_string(),
            ),
            ..Default::default()
        }
    }
}
