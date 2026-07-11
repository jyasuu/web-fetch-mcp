use url::Url;

/// Fetches robots.txt for the URL's origin and checks whether the given path
/// is disallowed for the "*" user-agent group. This is a deliberately simple
/// prefix-match implementation (no wildcard/`$` support) — enough to respect
/// a normal robots.txt, not a full spec-compliant parser.
///
/// Returns `Ok(true)` if fetching is allowed (including when robots.txt is
/// missing or unreachable — absence of robots.txt means "allowed").
pub async fn is_allowed(client: &reqwest::Client, url: &Url) -> bool {
    let mut robots_url = url.clone();
    robots_url.set_path("/robots.txt");
    robots_url.set_query(None);

    let body = match client
        .get(robots_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
    {
        Ok(resp) => match resp.text().await {
            Ok(text) => text,
            Err(_) => return true,
        },
        Err(_) => return true, // no robots.txt, or it errored -> treat as allowed
    };

    let path = url.path();
    let mut in_star_group = false;
    let mut disallows: Vec<String> = Vec::new();

    for line in body.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();

        match key.as_str() {
            "user-agent" => {
                in_star_group = value == "*";
            }
            "disallow" if in_star_group && !value.is_empty() => {
                disallows.push(value.to_string());
            }
            _ => {}
        }
    }

    !disallows.iter().any(|d| path.starts_with(d.as_str()))
}
