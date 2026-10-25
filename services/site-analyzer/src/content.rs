use std::{
    collections::{HashMap, HashSet},
    hash::{Hash, Hasher},
    sync::OnceLock,
};

use jieba_rs::Jieba;
use minhash_rs::prelude::{LshIndex, MinHash, QueryState, Store};
use serde::Serialize;

use crate::PageInput;

const PAGE_KEYWORD_LIMIT: usize = 8;
const SITE_KEYWORD_LIMIT: usize = 30;
const MAX_GROUPS: usize = 100;
const MAX_GROUP_PAGES: usize = 100;
const MINHASH_PERMUTATIONS: usize = 128;
const MINHASH_BANDS: usize = 16;
const CONTENT_SHINGLE_SIZE: usize = 5;
const SIMILARITY_THRESHOLD: f64 = 0.8;

#[derive(Debug, Clone, Serialize)]
pub struct KeywordScore {
    pub term: String,
    pub score: f64,
    pub frequency: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentHeading {
    pub level: u8,
    pub text: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentPageMetrics {
    pub word_count: usize,
    pub character_count: usize,
    pub language: String,
    pub headings: Vec<ContentHeading>,
    pub keywords: Vec<KeywordScore>,
    pub thin_content: bool,
    pub suspected_access_challenge: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentPageRef {
    pub url: String,
    pub title: Option<String>,
    pub word_count: usize,
    pub character_count: usize,
    pub inbound_links: usize,
    pub keywords: Vec<KeywordScore>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentGroup {
    pub pages: Vec<ContentPageRef>,
    pub recommended_page: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentAnalysis {
    pub pages_with_content: usize,
    pub thin_content_pages: usize,
    pub thin_pages: Vec<ContentPageRef>,
    pub thin_pages_truncated: bool,
    pub exact_duplicate_groups: Vec<ContentGroup>,
    pub similar_content_groups: Vec<ContentGroup>,
    pub keyword_overlap_groups: Vec<ContentGroup>,
    pub top_keywords: Vec<KeywordScore>,
    pub groups_truncated: bool,
}

pub fn analyze(
    pages: &[PageInput],
    inbound: &HashMap<String, usize>,
) -> (ContentAnalysis, Vec<ContentPageMetrics>) {
    static JIEBA: OnceLock<Jieba> = OnceLock::new();
    let jieba = JIEBA.get_or_init(Jieba::new);
    let mut documents = Vec::with_capacity(pages.len());
    let mut document_frequency = HashMap::<String, usize>::new();
    let mut fingerprint_frequency = HashMap::<&str, usize>::new();
    for page in pages {
        if let Some(fingerprint) = page.body_fingerprint.as_deref() {
            *fingerprint_frequency.entry(fingerprint).or_default() += 1;
        }
    }
    let mut pages_with_content = 0usize;
    let mut thin_content_pages = 0usize;
    let brand_terms = site_brand_terms(pages);

    for page in pages {
        let text = page.content_text.as_deref().unwrap_or_default();
        let suspected_challenge = page.redirect_chain.is_empty()
            && !page
                .status_code
                .is_some_and(|status| matches!(status, 301 | 302 | 303 | 307 | 308))
            && page
                .body_fingerprint
                .as_deref()
                .is_some_and(|fp| fingerprint_frequency.get(fp).copied().unwrap_or_default() >= 3)
            && page.response_size_bytes.is_some_and(|size| size <= 20_000)
            && text.chars().count() < 100;
        let suspected_challenge = suspected_challenge
            && (page
                .title
                .as_deref()
                .is_none_or(|title| title.trim().is_empty())
                || page.h1_count == 0);
        let is_html = page
            .content_type
            .as_deref()
            .is_none_or(crate::is_html_content_type);
        let eligible = is_html
            && page.error.is_none()
            && page.redirect_chain.is_empty()
            && !page
                .status_code
                .is_some_and(|status| matches!(status, 301 | 302 | 303 | 307 | 308))
            && page
                .status_code
                .is_none_or(|status| (200..400).contains(&status))
            && !suspected_challenge;
        let tokens = if eligible {
            let mut tokens = tokenize(&jieba, text);
            tokens.retain(|token| !brand_terms.contains(token));
            tokens
        } else {
            Vec::new()
        };
        let character_count = text.chars().filter(|ch| !ch.is_whitespace()).count();
        let cjk_count = text.chars().filter(|ch| is_cjk(*ch)).count();
        let language = if cjk_count == 0 {
            if tokens.is_empty() {
                "unknown"
            } else {
                "english_or_other"
            }
        } else if cjk_count * 5 >= character_count {
            "chinese"
        } else {
            "mixed"
        };
        let thin = eligible
            && if cjk_count * 5 >= character_count && cjk_count > 0 {
                cjk_count < 300
            } else {
                tokens.len() < 100
            };
        if eligible && !tokens.is_empty() {
            pages_with_content += 1;
        }
        if thin {
            thin_content_pages += 1;
        }
        let unique = tokens.iter().cloned().collect::<HashSet<_>>();
        for token in unique {
            *document_frequency.entry(token).or_default() += 1;
        }
        documents.push((
            tokens,
            character_count,
            language.to_owned(),
            thin,
            suspected_challenge,
        ));
    }

    let doc_count = documents.len().max(1) as f64;
    let mut page_metrics = Vec::with_capacity(pages.len());
    let mut site_scores = HashMap::<String, f64>::new();
    let mut site_frequencies = HashMap::<String, usize>::new();
    let mut page_term_sets = Vec::with_capacity(pages.len());
    let mut page_shingles = Vec::with_capacity(pages.len());

    for (page, (tokens, character_count, language, thin, suspected_challenge)) in
        pages.iter().zip(documents.iter())
    {
        let mut frequencies = HashMap::<String, usize>::new();
        for token in tokens {
            *frequencies.entry(token.clone()).or_default() += 1;
        }
        let token_count = tokens.len().max(1) as f64;
        let mut scores = frequencies
            .iter()
            .map(|(term, count)| {
                let df = document_frequency.get(term).copied().unwrap_or(1) as f64;
                let idf = if doc_count <= 1.0 {
                    1.0
                } else {
                    (doc_count / df).ln().max(0.0)
                };
                let score = (*count as f64 / token_count) * idf;
                (term.clone(), score)
            })
            .collect::<Vec<_>>();
        scores.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        for (term, score) in &scores {
            *site_scores.entry(term.clone()).or_default() += score;
        }
        for (term, count) in &frequencies {
            *site_frequencies.entry(term.clone()).or_default() += count;
        }
        page_term_sets.push(
            scores
                .iter()
                .take(PAGE_KEYWORD_LIMIT)
                .map(|(term, _)| term.clone())
                .collect::<HashSet<_>>(),
        );
        page_shingles.push(content_shingles(tokens));
        let headings = page
            .headings
            .iter()
            .take(100)
            .map(|heading| ContentHeading {
                level: heading.level,
                text: heading.text.clone(),
            })
            .collect();
        page_metrics.push(ContentPageMetrics {
            word_count: tokens.len(),
            character_count: *character_count,
            language: language.clone(),
            headings,
            keywords: scores
                .into_iter()
                .take(PAGE_KEYWORD_LIMIT)
                .map(|(term, score)| KeywordScore {
                    frequency: frequencies.get(&term).copied().unwrap_or_default(),
                    term,
                    score,
                })
                .collect(),
            thin_content: *thin,
            suspected_access_challenge: *suspected_challenge,
        });
    }

    let mut top_keywords = site_scores
        .into_iter()
        .map(|(term, score)| KeywordScore {
            frequency: site_frequencies.get(&term).copied().unwrap_or_default(),
            term,
            score,
        })
        .collect::<Vec<_>>();
    top_keywords.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.frequency.cmp(&a.frequency))
            .then_with(|| a.term.cmp(&b.term))
    });
    top_keywords.truncate(SITE_KEYWORD_LIMIT);

    let thin_page_refs = pages
        .iter()
        .zip(&page_metrics)
        .enumerate()
        .filter(|(_, (_, metrics))| metrics.thin_content)
        .map(|(_, (page, metrics))| page_ref(page, metrics, inbound))
        .collect::<Vec<_>>();
    let thin_pages_truncated = thin_page_refs.len() > 200;
    let exact_groups = exact_duplicate_groups(pages, &page_metrics, inbound);
    let exact_fingerprints = pages
        .iter()
        .enumerate()
        .filter_map(|(index, page)| {
            let fingerprint = page.body_fingerprint.as_deref()?;
            let metrics = page_metrics.get(index)?;
            let eligible = page.error.is_none()
                && !page.partial_content
                && page.redirect_chain.is_empty()
                && page
                    .status_code
                    .is_none_or(|status| (200..400).contains(&status))
                && page
                    .content_type
                    .as_deref()
                    .is_none_or(crate::is_html_content_type)
                && !metrics.suspected_access_challenge;
            eligible.then_some((index, fingerprint))
        })
        .collect::<HashMap<_, _>>();
    let similar_pairs = similar_pairs(&page_shingles)
        .into_iter()
        .filter(|(left, right)| exact_fingerprints.get(left) != exact_fingerprints.get(right))
        .collect::<Vec<_>>();
    let similar_groups = groups_from_pairs(
        &similar_pairs,
        pages,
        &page_metrics,
        inbound,
        "Pages share highly similar body text; the suggested canonical page has the strongest internal linking.",
    );
    let overlap_pairs = keyword_overlap_pairs(&page_term_sets)
        .into_iter()
        .filter(|(a, b)| !hierarchical_urls(&pages[*a].url, &pages[*b].url))
        .collect::<Vec<_>>();
    let overlap_groups = pair_groups_from_pairs(
        &overlap_pairs,
        pages,
        &page_metrics,
        inbound,
        "Pages target several of the same high-weight terms; review their search intent and focus.",
    );
    let groups_truncated = exact_groups.len() > MAX_GROUPS
        || similar_groups.len() > MAX_GROUPS
        || overlap_groups.len() > MAX_GROUPS;

    (
        ContentAnalysis {
            pages_with_content,
            thin_content_pages,
            thin_pages: thin_page_refs.into_iter().take(200).collect(),
            thin_pages_truncated,
            exact_duplicate_groups: exact_groups.into_iter().take(MAX_GROUPS).collect(),
            similar_content_groups: similar_groups.into_iter().take(MAX_GROUPS).collect(),
            keyword_overlap_groups: overlap_groups.into_iter().take(MAX_GROUPS).collect(),
            top_keywords,
            groups_truncated,
        },
        page_metrics,
    )
}

fn tokenize(jieba: &Jieba, text: &str) -> Vec<String> {
    static STOP_WORDS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    let stop_words = STOP_WORDS.get_or_init(stop_words);
    jieba
        .cut(text, false)
        .into_iter()
        .map(|token| token.word.trim().to_lowercase())
        .filter(|token| token.chars().any(char::is_alphanumeric))
        .filter(|token| token.chars().filter(|ch| ch.is_alphanumeric()).count() >= 2)
        .filter(|token| !stop_words.contains(token.as_str()))
        .filter(|token| !token.chars().all(|ch| ch.is_ascii_digit()))
        .collect()
}

fn stop_words() -> HashSet<&'static str> {
    let mut words = include_str!("../data/stopwords-en.txt")
        .lines()
        .map(str::trim)
        .filter(|word| !word.is_empty() && !word.starts_with('#'))
        .collect::<HashSet<_>>();
    words.extend([
        "的", "了", "和", "是", "在", "就", "都", "而", "及", "与", "着", "或", "一个", "没有",
        "我们", "你们", "他们", "以及", "因为", "所以", "如果", "这个", "这些", "那个", "那些",
        "可以", "进行", "通过", "对于", "作为", "被", "从", "到", "中", "上", "下", "也", "还",
        "等", "并", "但", "其", "之", "所", "为", "把", "让", "更", "很", "最", "已经", "需要",
        "使用", "提供", "支持", "网站",
    ]);
    words
}

fn is_cjk(ch: char) -> bool {
    matches!(ch as u32, 0x3400..=0x4DBF | 0x4E00..=0x9FFF | 0xF900..=0xFAFF)
}

fn content_shingles(tokens: &[String]) -> HashSet<u64> {
    if tokens.len() < CONTENT_SHINGLE_SIZE {
        return HashSet::new();
    }
    tokens
        .windows(CONTENT_SHINGLE_SIZE)
        .map(|window| {
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            for token in window {
                token.hash(&mut hasher);
                0xffu8.hash(&mut hasher);
            }
            hasher.finish()
        })
        .collect()
}

fn exact_duplicate_groups(
    pages: &[PageInput],
    metrics: &[ContentPageMetrics],
    inbound: &HashMap<String, usize>,
) -> Vec<ContentGroup> {
    let mut by_fingerprint = HashMap::<&str, Vec<usize>>::new();
    for (index, page) in pages.iter().enumerate() {
        let Some(fingerprint) = page.body_fingerprint.as_deref() else {
            continue;
        };
        let Some(metrics) = metrics.get(index) else {
            continue;
        };
        if page.error.is_some()
            || page.partial_content
            || !page.redirect_chain.is_empty()
            || page
                .status_code
                .is_some_and(|status| !(200..400).contains(&status))
            || page
                .content_type
                .as_deref()
                .is_some_and(|content_type| !crate::is_html_content_type(content_type))
            || metrics.suspected_access_challenge
        {
            continue;
        }
        by_fingerprint.entry(fingerprint).or_default().push(index);
    }

    let mut groups = by_fingerprint
        .into_values()
        .filter(|members| members.len() > 1)
        .map(|members| {
            let recommended = *members
                .iter()
                .max_by_key(|index| recommendation_rank(&pages[**index], inbound))
                .expect("duplicate group has at least two pages");
            let mut page_refs = members
                .iter()
                .map(|index| page_ref(&pages[*index], &metrics[*index], inbound))
                .collect::<Vec<_>>();
            page_refs.sort_by(|a, b| {
                b.inbound_links
                    .cmp(&a.inbound_links)
                    .then_with(|| a.url.cmp(&b.url))
            });
            ContentGroup {
                pages: page_refs.into_iter().take(MAX_GROUP_PAGES).collect(),
                recommended_page: normalize(&pages[recommended].url),
                reason: "The downloaded HTML is identical across these pages.".into(),
            }
        })
        .collect::<Vec<_>>();
    groups.sort_by(|a, b| {
        b.pages
            .len()
            .cmp(&a.pages.len())
            .then_with(|| a.recommended_page.cmp(&b.recommended_page))
    });
    groups
}

fn similar_pairs(shingles: &[HashSet<u64>]) -> Vec<(usize, usize)> {
    type Signature = MinHash<u64, MINHASH_PERMUTATIONS>;
    type SimilarityIndex = LshIndex<Signature, MINHASH_PERMUTATIONS, MINHASH_BANDS, Store>;

    let signatures = shingles
        .iter()
        .map(|page_shingles| page_shingles.iter().copied().collect::<Signature>())
        .collect::<Vec<_>>();
    if signatures.len() < 2 {
        return Vec::new();
    }
    let index = SimilarityIndex::from_signatures(signatures.iter().cloned());
    let mut query_state = QueryState::new();
    let mut pairs = HashSet::new();
    for (left, signature) in signatures.iter().enumerate() {
        for (right, _) in index.top_k(signature, signatures.len(), &mut query_state) {
            let right = right as usize;
            if left == right {
                continue;
            }
            let pair = (left.min(right), left.max(right));
            if pairs.contains(&pair) {
                continue;
            }
            let left_shingles = &shingles[pair.0];
            let right_shingles = &shingles[pair.1];
            if left_shingles.is_empty() || right_shingles.is_empty() {
                continue;
            }
            let intersection = left_shingles.intersection(right_shingles).count();
            let union = left_shingles.len() + right_shingles.len() - intersection;
            let jaccard = intersection as f64 / union as f64;
            if jaccard >= SIMILARITY_THRESHOLD {
                pairs.insert(pair);
            }
        }
    }
    pairs.into_iter().collect()
}

fn keyword_overlap_pairs(terms: &[HashSet<String>]) -> Vec<(usize, usize)> {
    let mut inverted = HashMap::<&str, Vec<usize>>::new();
    for (index, page_terms) in terms.iter().enumerate() {
        for term in page_terms {
            inverted.entry(term).or_default().push(index);
        }
    }
    let mut overlaps = HashMap::<(usize, usize), u8>::new();
    for members in inverted.values().filter(|members| members.len() <= 500) {
        for i in 0..members.len() {
            for j in i + 1..members.len() {
                let key = (members[i].min(members[j]), members[i].max(members[j]));
                *overlaps.entry(key).or_default() += 1;
            }
        }
    }
    overlaps
        .into_iter()
        .filter_map(|(pair, count)| (count >= 3).then_some(pair))
        .collect()
}

fn groups_from_pairs(
    pairs: &[(usize, usize)],
    pages: &[PageInput],
    metrics: &[ContentPageMetrics],
    inbound: &HashMap<String, usize>,
    reason: &str,
) -> Vec<ContentGroup> {
    let mut parent = (0..pages.len()).collect::<Vec<_>>();
    for (a, b) in pairs {
        let root_a = find_root(&mut parent, *a);
        let root_b = find_root(&mut parent, *b);
        if root_a != root_b {
            parent[root_b] = root_a;
        }
    }
    let mut grouped = HashMap::<usize, Vec<usize>>::new();
    for index in 0..pages.len() {
        let root = find_root(&mut parent, index);
        grouped.entry(root).or_default().push(index);
    }
    let mut groups = grouped
        .into_values()
        .filter(|members| members.len() > 1)
        .map(|members| {
            let recommended = *members
                .iter()
                .max_by_key(|index| recommendation_rank(&pages[**index], inbound))
                .unwrap();
            let recommended_url = normalize(&pages[recommended].url);
            let mut page_refs = members
                .into_iter()
                .map(|index| page_ref(&pages[index], &metrics[index], inbound))
                .collect::<Vec<_>>();
            page_refs.sort_by(|a, b| {
                b.inbound_links
                    .cmp(&a.inbound_links)
                    .then_with(|| a.url.cmp(&b.url))
            });
            ContentGroup {
                pages: page_refs.into_iter().take(MAX_GROUP_PAGES).collect(),
                recommended_page: recommended_url,
                reason: reason.to_owned(),
            }
        })
        .collect::<Vec<_>>();
    groups.sort_by(|a, b| {
        b.pages
            .len()
            .cmp(&a.pages.len())
            .then_with(|| a.recommended_page.cmp(&b.recommended_page))
    });
    groups
}

fn pair_groups_from_pairs(
    pairs: &[(usize, usize)],
    pages: &[PageInput],
    metrics: &[ContentPageMetrics],
    inbound: &HashMap<String, usize>,
    reason: &str,
) -> Vec<ContentGroup> {
    let mut groups = pairs
        .iter()
        .filter_map(|(a, b)| {
            let (a, b) = (*a, *b);
            let left = page_ref(&pages[a], &metrics[a], inbound);
            let right = page_ref(&pages[b], &metrics[b], inbound);
            let recommended = if recommendation_rank(&pages[a], inbound)
                >= recommendation_rank(&pages[b], inbound)
            {
                left.url.clone()
            } else {
                right.url.clone()
            };
            Some(ContentGroup {
                pages: vec![left, right],
                recommended_page: recommended,
                reason: reason.to_owned(),
            })
        })
        .collect::<Vec<_>>();
    groups.sort_by(|a, b| {
        a.pages
            .iter()
            .map(|p| p.inbound_links)
            .sum::<usize>()
            .cmp(&b.pages.iter().map(|p| p.inbound_links).sum::<usize>())
            .reverse()
            .then_with(|| a.recommended_page.cmp(&b.recommended_page))
    });
    groups
}

fn page_ref(
    page: &PageInput,
    metrics: &ContentPageMetrics,
    inbound: &HashMap<String, usize>,
) -> ContentPageRef {
    let url = normalize(&page.url);
    ContentPageRef {
        inbound_links: inbound.get(&url).copied().unwrap_or_default(),
        url,
        title: page.title.clone(),
        word_count: metrics.word_count,
        character_count: metrics.character_count,
        keywords: metrics.keywords.clone(),
    }
}

fn site_brand_terms(pages: &[PageInput]) -> HashSet<String> {
    let Some(host) = pages
        .first()
        .and_then(|page| url::Url::parse(&page.url).ok())
        .and_then(|url| url.host_str().map(str::to_owned))
    else {
        return HashSet::new();
    };
    let registrable = psl::domain_str(&host).unwrap_or(&host);
    registrable
        .split('.')
        .next()
        .unwrap_or_default()
        .split(['-', '_'])
        .filter(|term| term.len() >= 2)
        .map(str::to_ascii_lowercase)
        .collect()
}

fn hierarchical_urls(left: &str, right: &str) -> bool {
    let (Ok(left), Ok(right)) = (url::Url::parse(left), url::Url::parse(right)) else {
        return false;
    };
    if left.host_str() != right.host_str() {
        return false;
    }
    let left_segments = left
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();
    let right_segments = right
        .path_segments()
        .map(|segments| segments.collect::<Vec<_>>())
        .unwrap_or_default();
    let left_segments = left_segments
        .into_iter()
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let right_segments = right_segments
        .into_iter()
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    (left_segments.len() < right_segments.len() && right_segments.starts_with(&left_segments))
        || (right_segments.len() < left_segments.len()
            && left_segments.starts_with(&right_segments))
}

fn recommendation_rank(
    page: &PageInput,
    inbound: &HashMap<String, usize>,
) -> (bool, bool, bool, usize) {
    let url = normalize(&page.url);
    (
        page.title
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
        page.description
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty()),
        page.h1_count == 1,
        inbound.get(&url).copied().unwrap_or_default(),
    )
}

fn find_root(parent: &mut [usize], index: usize) -> usize {
    if parent[index] != index {
        parent[index] = find_root(parent, parent[index]);
    }
    parent[index]
}

fn normalize(value: &str) -> String {
    crate::normalize_url(value).unwrap_or_else(|| value.to_owned())
}
